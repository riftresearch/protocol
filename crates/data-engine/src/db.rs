use crate::models::{
    ChainAwareDeposit, ChainAwareProposedSwap, ChainAwareRelease, ChainAwareWithdraw, OTCSwap,
};
use alloy::{
    hex,
    primitives::{keccak256, Address},
    sol_types::SolValue,
};
use eyre::Result;
use rift_core::vaults::hash_deposit_vault;
use sol_bindings::Types::{DepositVault, ProposedSwap};
use std::str::FromStr;
use tokio_rusqlite::{params, Connection, Error::Rusqlite};
use tracing::info;

/// Run initial table creation / migrations on an existing `tokio_sqlite::Connection`.
pub async fn setup_swaps_database(conn: &Connection) -> Result<()> {
    let schema = r#"
        CREATE TABLE IF NOT EXISTS deposits (
            deposit_id            BLOB(32) PRIMARY KEY,
            depositor             TEXT      NOT NULL,
            recipient             TEXT      NOT NULL,
            deposit_unlock_timestamp INTEGER NOT NULL,
            deposit_vault         TEXT      NOT NULL,

            deposit_block_number  INTEGER   NOT NULL,
            deposit_block_hash    BLOB(32)  NOT NULL,
            deposit_txid          BLOB(32)  NOT NULL,

            withdraw_txid         BLOB(32),
            withdraw_block_number INTEGER,
            withdraw_block_hash   BLOB(32)
        );

        CREATE TABLE IF NOT EXISTS proposed_swaps (
            proposed_swap_id       BLOB(32)  PRIMARY KEY,
            deposit_id             BLOB(32)  NOT NULL,

            proposed_block_number  INTEGER   NOT NULL,
            proposed_block_hash    BLOB(32)  NOT NULL,
            proposed_txid          BLOB(32)  NOT NULL,
            challenge_period_end_timestamp INTEGER NOT NULL,

            swap_proof             TEXT      NOT NULL,
            release_txid  BLOB(32),
            release_block_number INTEGER,
            release_block_hash   BLOB(32),

            FOREIGN KEY (deposit_id)
                REFERENCES deposits(deposit_id)
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

pub fn get_proposed_swap_id(swap: &ProposedSwap) -> [u8; 32] {
    // This should be unique for each proposed swap
    let mut id_material = swap.depositVaultCommitment.to_vec();
    id_material.extend(swap.swapIndex.to_be_bytes::<32>().to_vec());
    keccak256(id_material).into()
}

pub async fn get_oldest_active_deposit(
    conn: &Connection,
    current_timestamp: u64,
) -> Result<Option<ChainAwareDeposit>> {
    let sql = r#"
        SELECT
            deposit_id,
            depositor,
            recipient,
            deposit_unlock_timestamp,
            deposit_vault,
            deposit_block_number,
            deposit_block_hash,
            deposit_txid
        FROM deposits
        WHERE deposit_unlock_timestamp > ?
        ORDER BY deposit_unlock_timestamp ASC
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
                let deposit_id_vec: Vec<u8> = row.get(0)?;
                let _depositor: String = row.get(1)?;
                let _recipient: String = row.get(2)?;
                let _deposit_unlock_timestamp: i64 = row.get(3)?;

                let deposit_vault_str: String = row.get(4)?;
                let deposit_vault: DepositVault = serde_json::from_str(&deposit_vault_str)
                    .map_err(|_| {
                        tokio_rusqlite::Error::Other("Failed to deserialize DepositVault".into())
                    })?;

                let deposit_block_number: i64 = row.get(5)?;
                let deposit_block_hash_vec: Vec<u8> = row.get(6)?;
                let deposit_block_hash: [u8; 32] =
                    deposit_block_hash_vec.as_slice().try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid deposit_block_hash length".into())
                    })?;

                let deposit_txid_vec: Vec<u8> = row.get(7)?;
                let deposit_txid: [u8; 32] =
                    deposit_txid_vec.as_slice().try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid deposit_txid length".into())
                    })?;

                Ok(Some(ChainAwareDeposit {
                    deposit: deposit_vault,
                    deposit_block_number: deposit_block_number as u64,
                    deposit_block_hash,
                    deposit_txid,
                }))
            } else {
                // No deposit matched the condition
                Ok(None)
            }
        })
        .await?;

    Ok(deposit)
}

pub async fn add_proposed_swap(
    conn: &Connection,
    swap: &ProposedSwap,
    swap_block_number: u64,
    swap_block_hash: [u8; 32],
    swap_txid: [u8; 32],
) -> Result<()> {
    let proposed_swap_id = get_proposed_swap_id(swap);
    let deposit_id = swap.depositVaultCommitment.to_vec();
    let swap_proof_str = serde_json::to_string(&swap)
        .map_err(|e| eyre::eyre!("Failed to serialize ProposedSwap: {:?}", e))?;
    let challenge_period_end_timestamp = swap.liquidityUnlockTimestamp;

    conn.call(move |conn| {
        conn.execute(
            r#"
        INSERT INTO proposed_swaps (
            proposed_swap_id,
            deposit_id,
            proposed_block_number,
            proposed_block_hash,
            proposed_txid,
            swap_proof,
            challenge_period_end_timestamp
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
            params![
                proposed_swap_id.to_vec(),
                deposit_id,
                swap_block_number as i64,
                swap_block_hash.to_vec(),
                swap_txid.to_vec(),
                swap_proof_str,
                challenge_period_end_timestamp
            ],
        )?;
        Ok(())
    })
    .await?;
    info!(
        message = "Proposed swap added",
        proposed_swap_id = hex::encode(proposed_swap_id),
        deposit_id = hex::encode(swap.depositVaultCommitment),
        operation = "add_proposed_swap"
    );
    Ok(())
}

pub async fn update_proposed_swap_to_released(
    conn: &Connection,
    proposed_swap_id: [u8; 32],
    release_txid: [u8; 32],
    release_block_number: u64,
    release_block_hash: [u8; 32],
) -> Result<()> {
    conn.call(move |conn| {
        conn.execute(
            r#"
        UPDATE proposed_swaps
        SET release_txid = ?1,
            release_block_number = ?2,
            release_block_hash = ?3
        WHERE proposed_swap_id = ?4
        "#,
            params![
                release_txid.to_vec(),
                release_block_number as i64,
                release_block_hash.to_vec(),
                proposed_swap_id.to_vec()
            ],
        )?;
        Ok(())
    })
    .await?;
    info!(
        message = "Proposed swap released",
        proposed_swap_id = hex::encode(proposed_swap_id),
        operation = "update_proposed_swap_to_released"
    );
    Ok(())
}

pub async fn update_deposit_to_withdrawn(
    conn: &Connection,
    deposit_id: [u8; 32],
    withdraw_txid: [u8; 32],
    withdraw_block_number: u64,
    withdraw_block_hash: [u8; 32],
) -> Result<()> {
    conn.call(move |conn| {
        conn.execute(
            r#"
        UPDATE deposits
        SET withdraw_txid = ?1,
            withdraw_block_number = ?2,
            withdraw_block_hash = ?3
        WHERE deposit_id = ?4
        "#,
            params![
                withdraw_txid.to_vec(),
                withdraw_block_number as i64,
                withdraw_block_hash.to_vec(),
                deposit_id.to_vec()
            ],
        )?;
        Ok(())
    })
    .await?;
    info!(
        message = "Deposit vault withdrawn",
        deposit_commitment = hex::encode(deposit_id)
    );
    Ok(())
}

pub async fn add_deposit(
    conn: &Connection,
    deposit: DepositVault,
    deposit_block_number: u64,
    deposit_block_hash: [u8; 32],
    deposit_txid: [u8; 32],
) -> Result<()> {
    let deposit_id = hash_deposit_vault(&deposit);
    let deposit_vault_str = serde_json::to_string(&deposit)
        .map_err(|e| eyre::eyre!("Failed to serialize DepositVault: {:?}", e))?;

    info!("Adding deposit: {:?}", hex::encode(deposit_id));

    conn.call(move |conn| {
        conn.execute(
            r#"
        INSERT INTO deposits (
            deposit_id,
            depositor,
            recipient,
            deposit_unlock_timestamp,
            deposit_vault,
            deposit_block_number,
            deposit_block_hash,
            deposit_txid
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
            params![
                deposit_id,
                deposit.ownerAddress.to_string(),
                deposit.specifiedPayoutAddress.to_string(),
                deposit.depositUnlockTimestamp,
                deposit_vault_str,
                deposit_block_number as i64,
                deposit_block_hash.to_vec(),
                deposit_txid.to_vec(),
            ],
        )?;
        Ok(())
    })
    .await?;
    info!(
        message = "Deposit added",
        deposit_commitment = hex::encode(deposit_id),
        deposit = format!("{:?}", deposit),
        operation = "add_deposit"
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
                deposit_id,            -- 0
                depositor,             -- 1
                recipient,             -- 2
                deposit_vault,         -- 3 (JSON-serialized DepositVault)
                deposit_block_number,  -- 4
                deposit_block_hash,    -- 5
                deposit_txid,          -- 6
                withdraw_txid,         -- 7
                withdraw_block_number, -- 8
                withdraw_block_hash    -- 9
            FROM deposits
            WHERE depositor = ?1 OR recipient = ?1
            ORDER BY deposit_block_number DESC
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
            let deposit_id_vec: Vec<u8> = row.get(0)?;
            let deposit_id: [u8; 32] = deposit_id_vec
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Failed to decode deposit_id".into()))?;

            // The deposit_vault column is JSON-serialized `DepositVault`
            let deposit_vault_str: String = row.get(3)?;
            let deposit_vault: DepositVault =
                serde_json::from_str(&deposit_vault_str).map_err(|e| {
                    tokio_rusqlite::Error::Other(
                        format!("Failed to deserialize DepositVault: {:?}", e).into(),
                    )
                })?;

            let deposit_block_number: i64 = row.get(4)?;
            let deposit_block_hash_vec: Vec<u8> = row.get(5)?;
            let deposit_block_hash: [u8; 32] = deposit_block_hash_vec.try_into().map_err(|_| {
                tokio_rusqlite::Error::Other("Invalid deposit_block_hash length".into())
            })?;

            let deposit_txid_vec: Vec<u8> = row.get(6)?;
            let deposit_txid: [u8; 32] = deposit_txid_vec
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid deposit_txid length".into()))?;

            // Withdraw columns are optional
            let withdraw_txid_vec: Option<Vec<u8>> = row.get(7)?;
            let withdraw_block_number: Option<i64> = row.get(8)?;
            let withdraw_block_hash_vec: Option<Vec<u8>> = row.get(9)?;

            // Assemble optional withdraw info
            let withdraw = if let (Some(txid_vec), Some(block_num), Some(block_hash_vec)) = (
                withdraw_txid_vec,
                withdraw_block_number,
                withdraw_block_hash_vec,
            ) {
                Some(ChainAwareWithdraw {
                    withdraw_txid: txid_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid withdraw_txid length".into())
                    })?,
                    withdraw_block_hash: block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid withdraw_block_hash length".into())
                    })?,
                    withdraw_block_number: block_num as u64,
                })
            } else {
                None
            };

            let chain_deposit = ChainAwareDeposit {
                deposit: deposit_vault,
                deposit_block_number: deposit_block_number as u64,
                deposit_block_hash,
                deposit_txid,
            };

            //
            // --- For each deposit, fetch all associated ProposedSwaps ---
            //
            let mut swap_stmt = conn.prepare(
                r#"
                SELECT
                    proposed_swap_id,            -- 0
                    deposit_id,                  -- 1
                    proposed_block_number,       -- 2
                    proposed_block_hash,         -- 3
                    proposed_txid,               -- 4
                    swap_proof,                  -- 5 (JSON-serialized ProposedSwap)
                    release_txid,       -- 6
                    release_block_number, -- 7
                    release_block_hash  -- 8
                FROM proposed_swaps
                WHERE deposit_id = ?1
                ORDER BY proposed_block_number ASC
                "#,
            )?;

            let mut swap_rows = swap_stmt.query(params![deposit_id])?;
            let mut swap_proofs = Vec::new();

            while let Some(swap_row) = swap_rows.next()? {
                //
                // --- Parse each ProposedSwap row ---
                //
                // We'll skip the deposit_id column from row (index=1) since we already know it.
                let proposed_block_number: i64 = swap_row.get(2)?;
                let proposed_block_hash_vec: Vec<u8> = swap_row.get(3)?;
                let proposed_block_hash: [u8; 32] =
                    proposed_block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid proposed_block_hash length".into())
                    })?;

                let proposed_txid_vec: Vec<u8> = swap_row.get(4)?;
                let proposed_txid: [u8; 32] = proposed_txid_vec.try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid proposed_txid length".into())
                })?;

                let swap_proof_str: String = swap_row.get(5)?;
                let swap: ProposedSwap = serde_json::from_str(&swap_proof_str).map_err(|e| {
                    tokio_rusqlite::Error::Other(
                        format!("Failed to deserialize ProposedSwap: {:?}", e).into(),
                    )
                })?;

                // release columns
                let release_txid_vec: Option<Vec<u8>> = swap_row.get(6)?;
                let release_block_number: Option<i64> = swap_row.get(7)?;
                let release_block_hash_vec: Option<Vec<u8>> = swap_row.get(8)?;

                let release =
                    if let (Some(rel_txid_vec), Some(rel_block_num), Some(rel_block_hash_vec)) = (
                        release_txid_vec,
                        release_block_number,
                        release_block_hash_vec,
                    ) {
                        Some(ChainAwareRelease {
                            release_txid: rel_txid_vec.try_into().map_err(|_| {
                                tokio_rusqlite::Error::Other("Invalid release_txid length".into())
                            })?,
                            release_block_hash: rel_block_hash_vec.try_into().map_err(|_| {
                                tokio_rusqlite::Error::Other(
                                    "Invalid release_block_hash length".into(),
                                )
                            })?,
                            release_block_number: rel_block_num as u64,
                        })
                    } else {
                        None
                    };

                let chain_swap = ChainAwareProposedSwap {
                    swap,
                    swap_proof_txid: proposed_txid,
                    swap_proof_block_hash: proposed_block_hash,
                    swap_proof_block_number: proposed_block_number as u64,
                    release,
                };

                swap_proofs.push(chain_swap);
            }

            // Finally assemble the OTCSwap
            let otcswap = OTCSwap {
                deposit: chain_deposit,
                swap_proofs,
                withdraw,
            };
            swaps.push(otcswap);
        }

        Ok(swaps)
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}

pub async fn get_deposits_for_recipient(
    conn: &Connection,
    address: Address,
    deposit_block_cutoff: u64,
) -> Result<Vec<DepositVault>> {
    let address_str = address.to_string();

    // Query for deposits where the recipient matches the provided address
    // and the deposit block number is greater than or equal to the cutoff
    conn.call(move |conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT
                deposit_vault         -- (JSON-serialized DepositVault)
            FROM deposits
            WHERE recipient = ?1 AND deposit_block_number >= ?2
            ORDER BY deposit_block_number ASC
            "#,
        )?;

        let mut rows = stmt.query(params![address_str, deposit_block_cutoff as i64])?;

        let mut deposits = Vec::new();

        while let Some(row) = rows.next()? {
            let deposit_vault_str: String = row.get(0)?;
            let deposit_vault: DepositVault =
                serde_json::from_str(&deposit_vault_str).map_err(|e| {
                    tokio_rusqlite::Error::Other(
                        format!("Failed to deserialize DepositVault: {:?}", e).into(),
                    )
                })?;

            deposits.push(deposit_vault);
        }

        Ok(deposits)
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}

pub async fn get_deposit_by_id(
    conn: &Connection,
    deposit_id: [u8; 32],
) -> Result<Option<ChainAwareDeposit>> {
    let sql = r#"
        SELECT
            deposit_vault,
            deposit_block_number,
            deposit_block_hash,
            deposit_txid
        FROM deposits
        WHERE deposit_id = ?
    "#;

    conn.call(move |conn| {
        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query(params![deposit_id.to_vec()])?;

        if let Some(row) = rows.next()? {
            // Parse deposit vault
            let deposit_vault_str: String = row.get(0)?;
            let deposit_vault: DepositVault =
                serde_json::from_str(&deposit_vault_str).map_err(|_| {
                    tokio_rusqlite::Error::Other("Failed to deserialize DepositVault".into())
                })?;

            // Parse block information
            let deposit_block_number: i64 = row.get(1)?;
            let deposit_block_hash_vec: Vec<u8> = row.get(2)?;
            let deposit_block_hash: [u8; 32] =
                deposit_block_hash_vec.as_slice().try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid deposit_block_hash length".into())
                })?;

            // Parse transaction ID
            let deposit_txid_vec: Vec<u8> = row.get(3)?;
            let deposit_txid: [u8; 32] = deposit_txid_vec
                .as_slice()
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid deposit_txid length".into()))?;

            Ok(Some(ChainAwareDeposit {
                deposit: deposit_vault,
                deposit_block_number: deposit_block_number as u64,
                deposit_block_hash,
                deposit_txid,
            }))
        } else {
            // No deposit found with this ID
            Ok(None)
        }
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}

pub struct ChainAwareProposedSwapWithDeposit {
    pub swap: ChainAwareProposedSwap,
    pub deposit: ChainAwareDeposit,
}

pub async fn get_swaps_ready_to_be_released(
    conn: &Connection,
    current_block_timestamp: u64,
) -> Result<Vec<ChainAwareProposedSwapWithDeposit>> {
    let sql = r#"
        SELECT
            ps.proposed_swap_id,
            ps.deposit_id,
            ps.proposed_block_number,
            ps.proposed_block_hash,
            ps.proposed_txid,
            ps.swap_proof,
            ps.release_txid,
            ps.release_block_number,
            ps.release_block_hash,
            ps.challenge_period_end_timestamp,

            d.deposit_vault,
            d.deposit_block_number,
            d.deposit_block_hash,
            d.deposit_txid
        FROM proposed_swaps ps
        JOIN deposits d ON ps.deposit_id = d.deposit_id
        WHERE ps.challenge_period_end_timestamp < ?
          AND ps.release_txid IS NULL
    "#;

    let swaps_with_deposit = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(sql)?;
            let mut rows = stmt.query(params![current_block_timestamp])?;

            let mut results = Vec::new();
            while let Some(row) = rows.next()? {
                //
                // --- ProposedSwap portion ---
                //
                let _proposed_swap_id_vec: Vec<u8> = row.get(0)?;
                let _deposit_id_vec: Vec<u8> = row.get(1)?;
                let proposed_block_number: i64 = row.get(2)?;
                let proposed_block_hash_vec: Vec<u8> = row.get(3)?;
                let proposed_block_hash: [u8; 32] =
                    proposed_block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid proposed_block_hash length".into())
                    })?;

                let proposed_txid_vec: Vec<u8> = row.get(4)?;
                let proposed_txid: [u8; 32] = proposed_txid_vec.try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid proposed_txid length".into())
                })?;

                let swap_proof_str: String = row.get(5)?;
                let swap: ProposedSwap = serde_json::from_str(&swap_proof_str).map_err(|e| {
                    tokio_rusqlite::Error::Other(
                        format!("Failed to deserialize ProposedSwap: {:?}", e).into(),
                    )
                })?;

                let release_txid_vec: Option<Vec<u8>> = row.get(6)?;
                let release_block_number: Option<i64> = row.get(7)?;
                let release_block_hash_vec: Option<Vec<u8>> = row.get(8)?;

                let release = if let (Some(txid_vec), Some(block_num), Some(block_hash_vec)) = (
                    release_txid_vec,
                    release_block_number,
                    release_block_hash_vec,
                ) {
                    Some(ChainAwareRelease {
                        release_txid: txid_vec.try_into().map_err(|_| {
                            tokio_rusqlite::Error::Other("Invalid release_txid length".into())
                        })?,
                        release_block_hash: block_hash_vec.try_into().map_err(|_| {
                            tokio_rusqlite::Error::Other("Invalid release_block_hash length".into())
                        })?,
                        release_block_number: block_num as u64,
                    })
                } else {
                    None
                };

                // This is the extra column. Read it here to avoid the mismatch:
                let _challenge_period_end_timestamp: i64 = row.get(9)?;

                //
                // --- Deposit portion ---
                //
                let deposit_vault_str: String = row.get(10)?;
                let deposit_vault: DepositVault = serde_json::from_str(&deposit_vault_str)
                    .map_err(|_| {
                        tokio_rusqlite::Error::Other("Failed to deserialize DepositVault".into())
                    })?;
                let deposit_block_number: i64 = row.get(11)?;
                let deposit_block_hash_vec: Vec<u8> = row.get(12)?;
                let deposit_block_hash: [u8; 32] =
                    deposit_block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid deposit_block_hash length".into())
                    })?;
                let deposit_txid_vec: Vec<u8> = row.get(13)?;
                let deposit_txid: [u8; 32] = deposit_txid_vec.try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid deposit_txid length".into())
                })?;

                let chain_deposit = ChainAwareDeposit {
                    deposit: deposit_vault,
                    deposit_block_number: deposit_block_number as u64,
                    deposit_block_hash,
                    deposit_txid,
                };

                let chain_swap = ChainAwareProposedSwap {
                    swap,
                    swap_proof_txid: proposed_txid,
                    swap_proof_block_hash: proposed_block_hash,
                    swap_proof_block_number: proposed_block_number as u64,
                    release,
                };

                //
                // --- Combine them ---
                //
                results.push(ChainAwareProposedSwapWithDeposit {
                    swap: chain_swap,
                    deposit: chain_deposit,
                });
            }
            Ok(results)
        })
        .await?;

    Ok(swaps_with_deposit)
}

pub async fn get_otc_swap_by_deposit_id(
    conn: &Connection,
    deposit_id: [u8; 32],
) -> Result<Option<OTCSwap>> {
    // We'll do this in a single `conn.call` closure to keep it consistent.
    conn.call(move |conn| {
        // 1) First, grab the deposit row.
        let mut deposit_stmt = conn.prepare(
            r#"
            SELECT
                deposit_vault,
                deposit_block_number,
                deposit_block_hash,
                deposit_txid,

                withdraw_txid,
                withdraw_block_number,
                withdraw_block_hash
            FROM deposits
            WHERE deposit_id = ?
            "#,
        )?;

        let mut deposit_rows = deposit_stmt.query(params![deposit_id.to_vec()])?;

        // If there's no row returned for this deposit_id, we return Ok(None).
        let (chain_deposit, withdraw) = if let Some(deposit_row) = deposit_rows.next()? {
            // Parse deposit
            let deposit_vault_str: String = deposit_row.get(0)?;
            let deposit_vault: DepositVault =
                serde_json::from_str(&deposit_vault_str).map_err(|e| {
                    tokio_rusqlite::Error::Other(
                        format!("Failed to deserialize DepositVault: {:?}", e).into(),
                    )
                })?;

            let deposit_block_number: i64 = deposit_row.get(1)?;
            let deposit_block_hash_vec: Vec<u8> = deposit_row.get(2)?;
            let deposit_block_hash: [u8; 32] = deposit_block_hash_vec.try_into().map_err(|_| {
                tokio_rusqlite::Error::Other("Invalid deposit_block_hash length".into())
            })?;

            let deposit_txid_vec: Vec<u8> = deposit_row.get(3)?;
            let deposit_txid: [u8; 32] = deposit_txid_vec
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid deposit_txid length".into()))?;

            // Parse optional withdraw columns
            let withdraw_txid_vec: Option<Vec<u8>> = deposit_row.get(4)?;
            let withdraw_block_number: Option<i64> = deposit_row.get(5)?;
            let withdraw_block_hash_vec: Option<Vec<u8>> = deposit_row.get(6)?;

            // Construct optional ChainAwareWithdraw if present
            let withdraw = if let (Some(txid_vec), Some(block_num), Some(block_hash_vec)) = (
                withdraw_txid_vec,
                withdraw_block_number,
                withdraw_block_hash_vec,
            ) {
                Some(ChainAwareWithdraw {
                    withdraw_txid: txid_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid withdraw_txid length".into())
                    })?,
                    withdraw_block_hash: block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid withdraw_block_hash length".into())
                    })?,
                    withdraw_block_number: block_num as u64,
                })
            } else {
                None
            };

            // Build ChainAwareDeposit
            let chain_deposit = ChainAwareDeposit {
                deposit: deposit_vault,
                deposit_block_number: deposit_block_number as u64,
                deposit_block_hash,
                deposit_txid,
            };

            (chain_deposit, withdraw)
        } else {
            // No deposit found, return early
            return Ok(None);
        };

        // 2) Now, fetch all ProposedSwaps for this deposit.
        let mut swaps_stmt = conn.prepare(
            r#"
            SELECT
                proposed_swap_id,            -- 0
                deposit_id,                  -- 1
                proposed_block_number,       -- 2
                proposed_block_hash,         -- 3
                proposed_txid,               -- 4
                swap_proof,                  -- 5 (JSON-serialized ProposedSwap)
                release_txid,       -- 6
                release_block_number, -- 7
                release_block_hash  -- 8
            FROM proposed_swaps
            WHERE deposit_id = ?
            ORDER BY proposed_block_number ASC
            "#,
        )?;

        let mut swap_rows = swaps_stmt.query(params![deposit_id.to_vec()])?;
        let mut swap_proofs = Vec::new();

        while let Some(swap_row) = swap_rows.next()? {
            // We skip the deposit_id column (index=1) since we already know it
            let proposed_block_number: i64 = swap_row.get(2)?;
            let proposed_block_hash_vec: Vec<u8> = swap_row.get(3)?;
            let proposed_block_hash: [u8; 32] =
                proposed_block_hash_vec.try_into().map_err(|_| {
                    tokio_rusqlite::Error::Other("Invalid proposed_block_hash length".into())
                })?;

            let proposed_txid_vec: Vec<u8> = swap_row.get(4)?;
            let proposed_txid: [u8; 32] = proposed_txid_vec
                .try_into()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid proposed_txid length".into()))?;

            let swap_proof_str: String = swap_row.get(5)?;
            let proposed_swap: ProposedSwap =
                serde_json::from_str(&swap_proof_str).map_err(|e| {
                    tokio_rusqlite::Error::Other(
                        format!("Failed to deserialize ProposedSwap: {:?}", e).into(),
                    )
                })?;

            // Release columns
            let release_txid_vec: Option<Vec<u8>> = swap_row.get(6)?;
            let release_block_number: Option<i64> = swap_row.get(7)?;
            let release_block_hash_vec: Option<Vec<u8>> = swap_row.get(8)?;

            let release = if let (Some(txid_vec), Some(block_num), Some(block_hash_vec)) = (
                release_txid_vec,
                release_block_number,
                release_block_hash_vec,
            ) {
                Some(ChainAwareRelease {
                    release_txid: txid_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid release_txid length".into())
                    })?,
                    release_block_hash: block_hash_vec.try_into().map_err(|_| {
                        tokio_rusqlite::Error::Other("Invalid release_block_hash length".into())
                    })?,
                    release_block_number: block_num as u64,
                })
            } else {
                None
            };

            let chain_swap = ChainAwareProposedSwap {
                swap: proposed_swap,
                swap_proof_txid: proposed_txid,
                swap_proof_block_hash: proposed_block_hash,
                swap_proof_block_number: proposed_block_number as u64,
                release,
            };

            swap_proofs.push(chain_swap);
        }

        // 3) Finally, assemble the OTCSwap.
        let otc_swap = OTCSwap {
            deposit: chain_deposit,
            swap_proofs,
            withdraw,
        };

        Ok(Some(otc_swap))
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}
