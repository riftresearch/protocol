use crate::models::{ChainAwareOrder, ChainAwarePayment, FinalizedTransaction, OTCSwap};
use alloy::{
    hex,
    primitives::{keccak256, Address},
    sol_types::SolValue,
};
use eyre::Result;
use rift_core::vaults::SolidityHash;
use sol_bindings::{Order, Payment};
use std::str::FromStr;
use tokio_rusqlite::{params, Connection, Error::Rusqlite};
use tracing::info;

/// Run initial table creation / migrations on an existing `tokio_sqlite::Connection`.
pub async fn setup_swaps_database(conn: &Connection) -> Result<()> {
    let schema = r#"
        CREATE TABLE IF NOT EXISTS orders (
            order_index         INTEGER PRIMARY KEY,
            initial_order_hash  BLOB(32)  NOT NULL,
            depositor           TEXT      NOT NULL,
            recipient           TEXT      NOT NULL,
            order_refund_timestamp INTEGER NOT NULL,

            order_json         TEXT      NOT NULL,
            order_block_number  INTEGER   NOT NULL,
            order_block_hash    BLOB(32)  NOT NULL,
            order_txid          BLOB(32)  NOT NULL,

            refund_txid         BLOB(32),
            refund_block_number INTEGER,
            refund_block_hash   BLOB(32)
        );

        CREATE TABLE IF NOT EXISTS payments (
            payment_index       INTEGER PRIMARY KEY,
            order_index         INTEGER  NOT NULL,

            payment_block_number  INTEGER   NOT NULL,
            payment_block_hash    BLOB(32)  NOT NULL,
            payment_txid          BLOB(32)  NOT NULL,
            challenge_period_end_timestamp INTEGER NOT NULL,

            payment_json             TEXT      NOT NULL,
            settlement_txid     BLOB(32),
            settlement_block_number INTEGER,
            settlement_block_hash   BLOB(32),

            FOREIGN KEY (order_index)
                REFERENCES orders(order_index)
                ON DELETE CASCADE
        );

    "#;

    conn.call(|conn| {
        conn.execute_batch(schema)?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn get_oldest_active_order(
    conn: &Connection,
    current_timestamp: u64,
) -> Result<Option<ChainAwareOrder>> {
    let sql = r#"
        SELECT
            order_index,
            depositor,
            recipient,
            order_refund_timestamp,
            order_json,
            order_block_number,
            order_block_hash,
            order_txid
        FROM orders
        WHERE order_refund_timestamp > ?
        ORDER BY order_refund_timestamp ASC
        LIMIT 1
    "#;

    // Use conn.call to run the query logic inside a single closure,
    // then parse the row in a step-by-step way similar to get_virtual_swaps.
    let deposit = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(sql)?;
            let mut rows = stmt.query([current_timestamp])?;

            // We only expect zero or one row because of `LIMIT 1`,
            // so just parse the first if present.
            if let Some(row) = rows.next()? {
                let _order_index: i64 = row.get(0)?;
                let _depositor: String = row.get(1)?;
                let _recipient: String = row.get(2)?;
                let _order_refund_timestamp: i64 = row.get(3)?;

                let order_json: String = row.get(4)?;
                let order: Order = serde_json::from_str(&order_json).map_err(|_| {
                    tokio_rusqlite::Error::Other("Failed to deserialize Order".into())
                })?;

                let order_block_number: i64 = row.get(5)?;
                let order_block_hash_vec: Vec<u8> = row.get(6)?;
                let order_block_hash: [u8; 32] =
                    order_block_hash_vec.as_slice().try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid order_block_hash length".into())
                    })?;

                let order_txid_vec: Vec<u8> = row.get(7)?;
                let order_txid: [u8; 32] = order_txid_vec.as_slice().try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid order_txid length".into())
                })?;

                Ok(Some(ChainAwareOrder {
                    order,
                    order_block_number: order_block_number as u64,
                    order_block_hash,
                    order_txid,
                }))
            } else {
                // No deposit matched the condition
                Ok(None)
            }
        })
        .await?;

    Ok(deposit)
}

pub async fn add_payment(
    conn: &Connection,
    payment: &Payment,
    payment_block_number: u64,
    payment_block_hash: [u8; 32],
    payment_txid: [u8; 32],
) -> Result<()> {
    let payment_index: u64 = payment.index.to();
    let order_index: u64 = payment.orderIndex.to();
    let payment_str = serde_json::to_string(&payment)
        .map_err(|e| eyre::eyre!("Failed to serialize Payment: {:?}", e))?;
    let challenge_period_end_timestamp = payment.challengeExpiryTimestamp;

    conn.call(move |conn| {
        conn.execute(
            r#"
        INSERT INTO payments (
            payment_index,
            order_index,
            payment_block_number,
            payment_block_hash,
            payment_txid,
            payment_json,
            challenge_period_end_timestamp
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
            params![
                payment_index,
                order_index,
                payment_block_number as i64,
                payment_block_hash.to_vec(),
                payment_txid.to_vec(),
                payment_str,
                challenge_period_end_timestamp
            ],
        )?;
        Ok(())
    })
    .await?;
    info!(
        message = "Payment added",
        payment_index = payment_index,
        order_index = order_index,
        operation = "add_payment"
    );
    Ok(())
}

pub async fn update_order_and_payment_to_settled(
    conn: &Connection,
    order: Order,
    payment: Payment,
    settlement_txid: [u8; 32],
    settlement_block_number: u64,
    settlement_block_hash: [u8; 32],
) -> Result<()> {
    let order_json = serde_json::to_string(&order)
        .map_err(|e| eyre::eyre!("Failed to serialize Order: {:?}", e))?;

    let payment_index = payment.index.to::<u64>();
    let order_index = order.index.to::<u64>();

    conn.call(move |conn| {
        // Start a transaction
        let tx = conn.transaction()?;

        // Update the order
        tx.execute(
            r#"
            UPDATE orders
            SET order_json = ?1
            WHERE order_index = ?2
            "#,
            params![order_json, order_index],
        )?;

        // Update the payment
        tx.execute(
            r#"
            UPDATE payments
            SET settlement_txid = ?1,
                settlement_block_number = ?2,
                settlement_block_hash = ?3
            WHERE payment_index = ?4
              AND order_index = ?5
            "#,
            params![
                settlement_txid.to_vec(),
                settlement_block_number as i64,
                settlement_block_hash.to_vec(),
                payment_index,
                order_index,
            ],
        )?;

        // Commit the transaction
        tx.commit()?;
        Ok(())
    })
    .await?;

    info!(
        message = "Order and payment settled",
        order_index = order_index,
        payment_index = payment_index,
        operation = "update_order_and_payment_to_settled"
    );
    Ok(())
}

pub async fn update_order_to_refunded(
    conn: &Connection,
    order: Order,
    refund_txid: [u8; 32],
    refund_block_number: u64,
    refund_block_hash: [u8; 32],
) -> Result<()> {
    let order_json = serde_json::to_string(&order)
        .map_err(|e| eyre::eyre!("Failed to serialize Order: {:?}", e))?;

    conn.call(move |conn| {
        conn.execute(
            r#"
        UPDATE orders
        SET refund_txid = ?1,
            refund_block_number = ?2,
            refund_block_hash = ?3,
            order_json = ?4
        WHERE order_index = ?5
        "#,
            params![
                refund_txid.to_vec(),
                refund_block_number as i64,
                refund_block_hash.to_vec(),
                order_json,
                order.index.to::<u64>(),
            ],
        )?;
        Ok(())
    })
    .await?;
    info!(
        message = "Order refunded",
        order_index = order.index.to::<u64>(),
        operation = "update_order_to_refunded"
    );
    Ok(())
}

pub async fn add_order(
    conn: &Connection,
    order: Order,
    order_block_number: u64,
    order_block_hash: [u8; 32],
    order_txid: [u8; 32],
) -> Result<()> {
    let order_json = serde_json::to_string(&order)
        .map_err(|e| eyre::eyre!("Failed to serialize Order: {:?}", e))?;

    let initial_order_hash = order.hash();

    conn.call(move |conn| {
        conn.execute(
            r#"
        INSERT INTO orders (
            order_index,
            initial_order_hash,
            depositor,
            recipient,
            order_refund_timestamp,
            order_json,
            order_block_number,
            order_block_hash,
            order_txid
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
            params![
                order.index.to::<u64>(),
                initial_order_hash,
                order.owner.to_string(),
                order.designatedReceiver.to_string(),
                order.unlockTimestamp,
                order_json,
                order_block_number as i64,
                order_block_hash.to_vec(),
                order_txid.to_vec(),
            ],
        )?;
        Ok(())
    })
    .await?;
    info!(
        message = "Order added",
        order_index = order.index.to::<u64>(),
        order = format!("{:?}", order),
        operation = "add_order"
    );

    Ok(())
}

// a user's swaps are defined as depositor == user.address or recipient == user.address
// note that explicit "maker/taker" doesn't really make sense at the OTC level, b/c the true
// maker could be a recipient if the user's vault is created via an intent

pub async fn get_virtual_swaps(
    conn: &Connection,
    address: Address,
    page: u32,
    page_size: u32,
) -> Result<Vec<OTCSwap>> {
    let offset = page * page_size;
    let address_str = address.to_string();

    // The main query for the relevant deposits.
    // We limit by `page_size` and offset by `(page * page_size)`.
    conn.call(move |conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT
                -- columns in the deposits table
                order_index,            -- 0
                depositor,             -- 1
                recipient,             -- 2
                order_json,         -- 3 (JSON-serialized Order)
                order_block_number,  -- 4
                order_block_hash,    -- 5
                order_txid,          -- 6
                refund_txid,         -- 7
                refund_block_number, -- 8
                refund_block_hash    -- 9
            FROM orders
            WHERE depositor = ?1 OR recipient = ?1
            ORDER BY order_block_number DESC
            LIMIT ?2
            OFFSET ?3
            "#,
        )?;

        let mut rows = stmt.query(params![address_str, page_size as i64, offset as i64])?;

        let mut swaps = Vec::new();

        while let Some(row) = rows.next()? {
            //
            // --- Parse the deposit-level data ---
            //
            let order_index: i64 = row.get(0)?;
            let _depositor: String = row.get(1)?; // we don't need it but keep the index
            let _recipient: String = row.get(2)?;
            let _order_refund_timestamp: i64 = row.get(3)?;

            let order_json: String = row.get(4)?;
            let order: Order = serde_json::from_str(&order_json).map_err(|e| {
                tokio_rusqlite::Error::Other(format!("Failed to deserialize Order: {:?}", e).into())
            })?;

            let order_block_number: i64 = row.get(5)?;
            let order_block_hash_vec: Vec<u8> = row.get(6)?;
            let order_block_hash: [u8; 32] = order_block_hash_vec.try_into().map_err(|_| {
                tokio_rusqlite::Error::Other("Invalid order_block_hash length".into())
            })?;

            let order_txid_vec: Vec<u8> = row.get(7)?;
            let order_txid: [u8; 32] = order_txid_vec
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid order_txid length".into()))?;

            // Withdraw columns are optional
            let refund_txid_vec: Option<Vec<u8>> = row.get(8)?;
            let refund_block_number: Option<i64> = row.get(9)?;
            let refund_block_hash_vec: Option<Vec<u8>> = row.get(10)?;

            // Assemble optional withdraw info
            let withdraw = if let (Some(txid_vec), Some(block_num), Some(block_hash_vec)) =
                (refund_txid_vec, refund_block_number, refund_block_hash_vec)
            {
                Some(FinalizedTransaction {
                    txid: txid_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid refund_txid length".into())
                    })?,
                    block_hash: block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid refund_block_hash length".into())
                    })?,
                    block_number: block_num as u64,
                })
            } else {
                None
            };

            let chain_order = ChainAwareOrder {
                order,
                order_block_number: order_block_number as u64,
                order_block_hash,
                order_txid,
            };

            //
            // --- For each order, fetch all associated payments ---
            //
            let mut swap_stmt = conn.prepare(
                r#"
                SELECT
                    payment_index,            -- 0
                    payment_block_number,     -- 1
                    payment_block_hash,       -- 2
                    payment_txid,             -- 3
                    payment_json,             -- 4
                    settlement_txid,          -- 5
                    settlement_block_number,  -- 6
                    settlement_block_hash,    -- 7
                    challenge_period_end_timestamp -- 8
                FROM payments
                WHERE order_index = ?1
                ORDER BY payment_block_number ASC
                "#,
            )?;

            let mut swap_rows = swap_stmt.query(params![order_index])?;
            let mut payments = Vec::new();

            while let Some(swap_row) = swap_rows.next()? {
                //
                // --- Parse each Payment row ---
                //
                let payment_block_number: i64 = swap_row.get(1)?;
                let payment_block_hash_vec: Vec<u8> = swap_row.get(2)?;
                let payment_block_hash: [u8; 32] =
                    payment_block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid payment_block_hash length".into())
                    })?;

                let payment_txid_vec: Vec<u8> = swap_row.get(3)?;
                let payment_txid: [u8; 32] = payment_txid_vec.try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid payment_txid length".into())
                })?;

                let payment_str: String = swap_row.get(4)?;
                let payment: Payment = serde_json::from_str(&payment_str).map_err(|e| {
                    tokio_rusqlite::Error::Other(
                        format!("Failed to deserialize Payment: {:?}", e).into(),
                    )
                })?;

                let settlement_txid_vec: Option<Vec<u8>> = swap_row.get(5)?;
                let settlement_block_number: Option<i64> = swap_row.get(6)?;
                let settlement_block_hash_vec: Option<Vec<u8>> = swap_row.get(7)?;

                let settlement = if let (
                    Some(settlement_txid_vec),
                    Some(settlement_block_number),
                    Some(settlement_block_hash_vec),
                ) = (
                    settlement_txid_vec,
                    settlement_block_number,
                    settlement_block_hash_vec,
                ) {
                    Some(FinalizedTransaction {
                        txid: settlement_txid_vec.try_into().map_err(|_| {
                            tokio_rusqlite::Error::Other("Invalid settlement_txid length".into())
                        })?,
                        block_hash: settlement_block_hash_vec.try_into().map_err(|_| {
                            tokio_rusqlite::Error::Other(
                                "Invalid settlement_block_hash length".into(),
                            )
                        })?,
                        block_number: settlement_block_number as u64,
                    })
                } else {
                    None
                };

                let chain_payment = ChainAwarePayment {
                    payment,
                    creation: FinalizedTransaction {
                        txid: payment_txid,
                        block_hash: payment_block_hash,
                        block_number: payment_block_number as u64,
                    },
                    settlement,
                };

                payments.push(chain_payment);
            }

            // Finally assemble the OTCSwap
            let otcswap = OTCSwap {
                order: chain_order,
                payments,
                refund: withdraw,
            };
            swaps.push(otcswap);
        }

        Ok(swaps)
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}

pub async fn get_orders_for_recipient(
    conn: &Connection,
    address: Address,
    order_block_cutoff: u64,
) -> Result<Vec<Order>> {
    let address_str = address.to_string();

    // Query for deposits where the recipient matches the provided address
    // and the deposit block number is greater than or equal to the cutoff
    conn.call(move |conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT
                order_json         -- (JSON-serialized Order)
            FROM orders
            WHERE recipient = ?1 AND order_block_number >= ?2
            ORDER BY order_block_number ASC
            "#,
        )?;

        let mut rows = stmt.query(params![address_str, order_block_cutoff as i64])?;

        let mut orders = Vec::new();

        while let Some(row) = rows.next()? {
            let order_str: String = row.get(0)?;
            let order: Order = serde_json::from_str(&order_str).map_err(|e| {
                tokio_rusqlite::Error::Other(format!("Failed to deserialize Order: {:?}", e).into())
            })?;

            orders.push(order);
        }

        Ok(orders)
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}

pub async fn get_order_by_initial_hash(
    conn: &Connection,
    initial_order_hash: [u8; 32],
) -> Result<Option<ChainAwareOrder>> {
    let sql = r#"
        SELECT
            order_json,
            order_block_number,
            order_block_hash,
            order_txid
        FROM orders
        WHERE initial_order_hash = ?
    "#;

    conn.call(move |conn| {
        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query(params![initial_order_hash])?;

        if let Some(row) = rows.next()? {
            // Parse deposit vault
            let order_str: String = row.get(0)?;
            let order: Order = serde_json::from_str(&order_str)
                .map_err(|_| tokio_rusqlite::Error::Other("Failed to deserialize Order".into()))?;

            // Parse block information
            let order_block_number: i64 = row.get(1)?;
            let order_block_hash_vec: Vec<u8> = row.get(2)?;
            let order_block_hash: [u8; 32] =
                order_block_hash_vec.as_slice().try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid order_block_hash length".into())
                })?;

            // Parse transaction ID
            let order_txid_vec: Vec<u8> = row.get(3)?;
            let order_txid: [u8; 32] = order_txid_vec
                .as_slice()
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid order_txid length".into()))?;

            Ok(Some(ChainAwareOrder {
                order,
                order_block_number: order_block_number as u64,
                order_block_hash,
                order_txid,
            }))
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}

pub async fn get_order_by_index(
    conn: &Connection,
    order_index: u64,
) -> Result<Option<ChainAwareOrder>> {
    let sql = r#"
        SELECT
            order_json,
            order_block_number,
            order_block_hash,
            order_txid
        FROM orders
        WHERE order_index = ?
    "#;

    conn.call(move |conn| {
        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query(params![order_index as i64])?;

        if let Some(row) = rows.next()? {
            // Parse deposit vault
            let order_str: String = row.get(0)?;
            let order: Order = serde_json::from_str(&order_str)
                .map_err(|_| tokio_rusqlite::Error::Other("Failed to deserialize Order".into()))?;

            // Parse block information
            let order_block_number: i64 = row.get(1)?;
            let order_block_hash_vec: Vec<u8> = row.get(2)?;
            let order_block_hash: [u8; 32] =
                order_block_hash_vec.as_slice().try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid order_block_hash length".into())
                })?;

            // Parse transaction ID
            let order_txid_vec: Vec<u8> = row.get(3)?;
            let order_txid: [u8; 32] = order_txid_vec
                .as_slice()
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid order_txid length".into()))?;

            Ok(Some(ChainAwareOrder {
                order,
                order_block_number: order_block_number as u64,
                order_block_hash,
                order_txid,
            }))
        } else {
            // No deposit found with this ID
            Ok(None)
        }
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}

pub struct ChainAwarePaymentWithOrder {
    pub payment: ChainAwarePayment,
    pub order: ChainAwareOrder,
}

pub async fn get_payments_ready_to_be_settled(
    conn: &Connection,
    current_block_timestamp: u64,
) -> Result<Vec<ChainAwarePaymentWithOrder>> {
    let sql = r#"
        SELECT
            ps.payment_index,
            ps.payment_block_number,
            ps.payment_block_hash,
            ps.payment_txid,
            ps.payment_json,
            ps.settlement_txid,
            ps.settlement_block_number,
            ps.settlement_block_hash,
            ps.challenge_period_end_timestamp,

            o.order_json,
            o.order_block_number,
            o.order_block_hash,
            o.order_txid
        FROM payments ps
        JOIN orders o ON ps.order_index = o.order_index
        WHERE ps.challenge_period_end_timestamp < ?
          AND ps.settlement_txid IS NULL
    "#;

    let payments_with_order = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(sql)?;
            let mut rows = stmt.query(params![current_block_timestamp])?;

            let mut results = Vec::new();
            while let Some(row) = rows.next()? {
                //
                // --- Payment portion ---
                //
                let payment_index: i64 = row.get(0)?;
                let payment_block_number: i64 = row.get(1)?;
                let payment_block_hash_vec: Vec<u8> = row.get(2)?;
                let payment_block_hash: [u8; 32] =
                    payment_block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid payment_block_hash length".into())
                    })?;

                let payment_txid_vec: Vec<u8> = row.get(3)?;
                let payment_txid: [u8; 32] = payment_txid_vec.try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid payment_txid length".into())
                })?;

                let payment_str: String = row.get(4)?;
                let payment: Payment = serde_json::from_str(&payment_str).map_err(|e| {
                    tokio_rusqlite::Error::Other(
                        format!("Failed to deserialize Payment: {:?}", e).into(),
                    )
                })?;

                let settlement_txid_vec: Option<Vec<u8>> = row.get(5)?;
                let settlement_block_number: Option<i64> = row.get(6)?;
                let settlement_block_hash_vec: Option<Vec<u8>> = row.get(7)?;

                let settlement = if let (Some(txid_vec), Some(block_num), Some(block_hash_vec)) = (
                    settlement_txid_vec,
                    settlement_block_number,
                    settlement_block_hash_vec,
                ) {
                    Some(FinalizedTransaction {
                        txid: txid_vec.try_into().map_err(|_| {
                            tokio_rusqlite::Error::Other("Invalid settlement_txid length".into())
                        })?,
                        block_hash: block_hash_vec.try_into().map_err(|_| {
                            tokio_rusqlite::Error::Other(
                                "Invalid settlement_block_hash length".into(),
                            )
                        })?,
                        block_number: block_num as u64,
                    })
                } else {
                    None
                };

                // This is the extra column. Read it here to avoid the mismatch:
                let _challenge_period_end_timestamp: i64 = row.get(8)?;

                //
                // --- Deposit portion ---
                //
                let order_str: String = row.get(9)?;
                let order: Order = serde_json::from_str(&order_str).map_err(|_| {
                    tokio_rusqlite::Error::Other("Failed to deserialize Order".into())
                })?;
                let order_block_number: i64 = row.get(10)?;
                let order_block_hash_vec: Vec<u8> = row.get(11)?;
                let order_block_hash: [u8; 32] = order_block_hash_vec.try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid order_block_hash length".into())
                })?;
                let order_txid_vec: Vec<u8> = row.get(12)?;
                let order_txid: [u8; 32] = order_txid_vec.try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid order_txid length".into())
                })?;

                let chain_order = ChainAwareOrder {
                    order,
                    order_block_number: order_block_number as u64,
                    order_block_hash,
                    order_txid,
                };

                let chain_payment = ChainAwarePayment {
                    payment,
                    creation: FinalizedTransaction {
                        txid: payment_txid,
                        block_hash: payment_block_hash,
                        block_number: payment_block_number as u64,
                    },
                    settlement,
                };

                //
                // --- Combine them ---
                //
                results.push(ChainAwarePaymentWithOrder {
                    payment: chain_payment,
                    order: chain_order,
                });
            }
            Ok(results)
        })
        .await?;

    Ok(payments_with_order)
}

pub async fn get_otc_swap_by_order_index(
    conn: &Connection,
    order_index: u64,
) -> Result<Option<OTCSwap>> {
    // We'll do this in a single `conn.call` closure to keep it consistent.
    conn.call(move |conn| {
        // 1) First, grab the deposit row.
        let mut order_stmt = conn.prepare(
            r#"
            SELECT
                order_json,
                order_block_number,
                order_block_hash,
                order_txid,

                refund_txid,
                refund_block_number,
                refund_block_hash
            FROM orders
            WHERE order_index = ?
            "#,
        )?;

        let mut order_rows = order_stmt.query(params![order_index as i64])?;

        // If there's no row returned for this deposit_id, we return Ok(None).
        let (chain_order, refund) = if let Some(order_row) = order_rows.next()? {
            // Parse deposit
            let order_str: String = order_row.get(0)?;
            let order: Order = serde_json::from_str(&order_str).map_err(|e| {
                tokio_rusqlite::Error::Other(format!("Failed to deserialize Order: {:?}", e).into())
            })?;

            let order_block_number: i64 = order_row.get(1)?;
            let order_block_hash_vec: Vec<u8> = order_row.get(2)?;
            let order_block_hash: [u8; 32] = order_block_hash_vec.try_into().map_err(|_| {
                tokio_rusqlite::Error::Other("Invalid order_block_hash length".into())
            })?;

            let order_txid_vec: Vec<u8> = order_row.get(3)?;
            let order_txid: [u8; 32] = order_txid_vec
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid order_txid length".into()))?;

            // Parse optional withdraw columns
            let refund_txid_vec: Option<Vec<u8>> = order_row.get(4)?;
            let refund_block_number: Option<i64> = order_row.get(5)?;
            let refund_block_hash_vec: Option<Vec<u8>> = order_row.get(6)?;

            // Construct optional ChainAwareWithdraw if present
            let refund = if let (Some(txid_vec), Some(block_num), Some(block_hash_vec)) =
                (refund_txid_vec, refund_block_number, refund_block_hash_vec)
            {
                Some(FinalizedTransaction {
                    txid: txid_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid refund_txid length".into())
                    })?,
                    block_hash: block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid refund_block_hash length".into())
                    })?,
                    block_number: block_num as u64,
                })
            } else {
                None
            };

            // Build ChainAwareDeposit
            let chain_order = ChainAwareOrder {
                order,
                order_block_number: order_block_number as u64,
                order_block_hash,
                order_txid,
            };

            (chain_order, refund)
        } else {
            // No deposit found, return early
            return Ok(None);
        };

        // 2) Now, fetch all ProposedSwaps for this deposit.
        let mut payments_stmt = conn.prepare(
            r#"
            SELECT
                payment_index,            -- 0
                payment_block_number,     -- 1
                payment_block_hash,       -- 2
                payment_txid,             -- 3
                payment_json,             -- 4
                settlement_txid,          -- 5
                settlement_block_number,  -- 6
                settlement_block_hash     -- 7
            FROM payments
            WHERE order_index = ?
            ORDER BY payment_block_number ASC
            "#,
        )?;

        let mut payment_rows = payments_stmt.query(params![order_index as i64])?;
        let mut payments = Vec::new();

        while let Some(payment_row) = payment_rows.next()? {
            let payment_block_number: i64 = payment_row.get(1)?;
            let payment_block_hash_vec: Vec<u8> = payment_row.get(2)?;
            let payment_block_hash: [u8; 32] = payment_block_hash_vec.try_into().map_err(|_| {
                tokio_rusqlite::Error::Other("Invalid payment_block_hash length".into())
            })?;

            let payment_txid_vec: Vec<u8> = payment_row.get(3)?;
            let payment_txid: [u8; 32] = payment_txid_vec
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid payment_txid length".into()))?;

            let payment_str: String = payment_row.get(4)?;
            let payment: Payment = serde_json::from_str(&payment_str).map_err(|e| {
                tokio_rusqlite::Error::Other(
                    format!("Failed to deserialize Payment: {:?}", e).into(),
                )
            })?;

            // Release columns
            let settlement_txid_vec: Option<Vec<u8>> = payment_row.get(5)?;
            let settlement_block_number: Option<i64> = payment_row.get(6)?;
            let settlement_block_hash_vec: Option<Vec<u8>> = payment_row.get(7)?;

            let settlement = if let (Some(txid_vec), Some(block_num), Some(block_hash_vec)) = (
                settlement_txid_vec,
                settlement_block_number,
                settlement_block_hash_vec,
            ) {
                Some(FinalizedTransaction {
                    txid: txid_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid settlement_txid length".into())
                    })?,
                    block_hash: block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid settlement_block_hash length".into())
                    })?,
                    block_number: block_num as u64,
                })
            } else {
                None
            };

            let chain_payment = ChainAwarePayment {
                payment,
                creation: FinalizedTransaction {
                    txid: payment_txid,
                    block_hash: payment_block_hash,
                    block_number: payment_block_number as u64,
                },
                settlement,
            };

            payments.push(chain_payment);
        }

        // 3) Finally, assemble the OTCSwap.
        let otc_swap = OTCSwap {
            order: chain_order,
            payments,
            refund,
        };

        Ok(Some(otc_swap))
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}
