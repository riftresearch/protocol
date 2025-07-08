//! Database operations for the Bitcoin transaction broadcaster.
//!
//! This module provides persistent storage for:
//! - UTXO management with locking mechanism
//! - Broadcasted transaction history and monitoring
//! - Parent-child transaction relationships for CPFP handling

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use eyre::Result;
use hex;
use tokio_rusqlite::{params, Connection};
use tracing::{debug, info};

/// Initialize the database schema for the Bitcoin transaction broadcaster.
///
/// Creates three main tables:
/// - `utxos`: Tracks all UTXOs owned by the wallet
/// - `broadcasted_txs`: History of all broadcasted transactions
/// - `tx_relationships`: Parent-child relationships for CPFP tracking
pub async fn setup_broadcaster_database(conn: &Connection) -> Result<()> {
    let schema = r#"
        -- Table for tracking UTXOs owned by the wallet
        CREATE TABLE IF NOT EXISTS utxos (
            -- Primary key: combination of txid and vout uniquely identifies a UTXO
            txid            BLOB(32)  NOT NULL,
            vout            INTEGER   NOT NULL,
            
            -- UTXO details
            value_sats      INTEGER   NOT NULL,
            script_pubkey   BLOB      NOT NULL,
            
            -- Status tracking
            confirmations   INTEGER   NOT NULL DEFAULT 0,
            is_locked       INTEGER   NOT NULL DEFAULT 0,  -- 0=available, 1=locked for pending tx
            is_spent        INTEGER   NOT NULL DEFAULT 0,  -- 0=unspent, 1=spent
            
            -- Timestamps for tracking
            created_at      INTEGER   NOT NULL,  -- Unix timestamp when UTXO was created
            locked_at       INTEGER,             -- Unix timestamp when locked (NULL if not locked)
            spent_at        INTEGER,             -- Unix timestamp when spent (NULL if not spent)
            
            -- The transaction that spent this UTXO (if any)
            spending_txid   BLOB(32),
            
            PRIMARY KEY (txid, vout)
        );
        
        -- Indexes for common queries
        CREATE INDEX IF NOT EXISTS idx_utxos_available ON utxos(is_locked, is_spent, value_sats);
        CREATE INDEX IF NOT EXISTS idx_utxos_confirmations ON utxos(confirmations);
        CREATE INDEX IF NOT EXISTS idx_utxos_spending_txid ON utxos(spending_txid);
        
        -- Table for tracking broadcasted transactions
        CREATE TABLE IF NOT EXISTS broadcasted_txs (
            txid                BLOB(32)  PRIMARY KEY,
            raw_tx              BLOB      NOT NULL,      -- Full serialized transaction
            fee_sats            INTEGER   NOT NULL,      -- Total fee in satoshis
            fee_rate_sat_vb     REAL      NOT NULL,      -- Fee rate in sat/vB
            
            -- Status tracking
            is_confirmed        INTEGER   NOT NULL DEFAULT 0,
            confirmations       INTEGER   NOT NULL DEFAULT 0,
            block_height        INTEGER,                  -- NULL until confirmed
            
            -- RBF tracking
            is_rbf_enabled      INTEGER   NOT NULL DEFAULT 1,  -- Whether tx signals RBF
            replaced_by_txid    BLOB(32),                      -- If this tx was replaced
            replaces_txid       BLOB(32),                      -- If this replaces another tx
            rbf_attempt_count   INTEGER   NOT NULL DEFAULT 0,  -- Number of RBF attempts
            last_rbf_attempt    INTEGER,                       -- Unix timestamp of last RBF attempt
            
            -- Timestamps
            broadcasted_at      INTEGER   NOT NULL,       -- Unix timestamp
            confirmed_at        INTEGER,                  -- Unix timestamp when first confirmed
            last_checked_at     INTEGER   NOT NULL,       -- Last time we checked mempool status
            
            -- Additional metadata
            num_inputs          INTEGER   NOT NULL,
            num_outputs         INTEGER   NOT NULL,
            weight              INTEGER   NOT NULL        -- Transaction weight in weight units
        );
        
        -- Indexes for transaction monitoring
        CREATE INDEX IF NOT EXISTS idx_txs_unconfirmed ON broadcasted_txs(is_confirmed, last_checked_at);
        CREATE INDEX IF NOT EXISTS idx_txs_replaced ON broadcasted_txs(replaced_by_txid);
        CREATE INDEX IF NOT EXISTS idx_txs_confirmations ON broadcasted_txs(confirmations);
        
        -- Table for tracking parent-child relationships (CPFP)
        CREATE TABLE IF NOT EXISTS tx_relationships (
            parent_txid     BLOB(32)  NOT NULL,
            child_txid      BLOB(32)  NOT NULL,
            child_input_idx INTEGER   NOT NULL,  -- Which input of child spends parent
            
            PRIMARY KEY (child_txid, child_input_idx),
            FOREIGN KEY (parent_txid) REFERENCES broadcasted_txs(txid),
            FOREIGN KEY (child_txid) REFERENCES broadcasted_txs(txid)
        );
        
        -- Index for finding all children of a parent
        CREATE INDEX IF NOT EXISTS idx_tx_rel_parent ON tx_relationships(parent_txid);
    "#;

    conn.call(|conn| {
        conn.execute_batch(schema)?;
        Ok(())
    })
    .await?;

    info!("Bitcoin transaction broadcaster database initialized");
    Ok(())
}

#[derive(Debug, Clone)]
pub struct DbUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    pub confirmations: u32,
    pub is_locked: bool,
    pub is_spent: bool,
    pub created_at: u64,
    pub locked_at: Option<u64>,
    pub spending_txid: Option<Txid>,
}

#[derive(Debug, Clone)]
pub struct DbTransaction {
    pub txid: Txid,
    pub raw_tx: Vec<u8>,
    pub fee: Amount,
    pub fee_rate_sat_vb: f64,
    pub confirmation_block: Option<i64>,
    pub confirmations: i64,
    pub is_rbf_enabled: bool,
    pub replaced_by: Option<Txid>,
    pub broadcasted_at: u64,
    pub last_checked: u64,
}

/// Add a new UTXO to the database
pub async fn add_utxo(
    conn: &Connection,
    outpoint: OutPoint,
    value: Amount,
    script_pubkey: ScriptBuf,
    created_at: u64,
) -> Result<()> {
    let txid = outpoint.txid.as_byte_array().to_vec();
    let vout = outpoint.vout;
    let value_sats = value.to_sat();
    let script_bytes = script_pubkey.as_bytes().to_vec();

    conn.call(move |conn| {
        conn.execute(
            r#"
            INSERT OR REPLACE INTO utxos (
                txid, vout, value_sats, script_pubkey, created_at, confirmations
            ) VALUES (?1, ?2, ?3, ?4, ?5, 0)
            "#,
            params![
                txid,
                vout,
                value_sats as i64,
                script_bytes,
                created_at as i64
            ],
        )?;
        Ok(())
    })
    .await?;

    info!(
        "Added UTXO: {}:{} with value {} sats",
        outpoint.txid, outpoint.vout, value_sats
    );
    Ok(())
}

/// Lock UTXOs for use in a pending transaction
pub async fn lock_utxos(
    conn: &Connection,
    outpoints: &[OutPoint],
    current_time: u64,
) -> Result<()> {
    // Convert outpoints to parameters
    let params: Vec<(Vec<u8>, u32)> = outpoints
        .iter()
        .map(|op| (op.txid.as_byte_array().to_vec(), op.vout))
        .collect();

    conn.call(move |conn| {
        let tx = conn.transaction()?;

        for (txid, vout) in params {
            let affected = tx.execute(
                r#"
                UPDATE utxos 
                SET is_locked = 1, locked_at = ?3
                WHERE txid = ?1 AND vout = ?2 AND is_locked = 0 AND is_spent = 0
                "#,
                params![txid, vout, current_time as i64],
            )?;

            if affected == 0 {
                return Err(tokio_rusqlite::Error::Other(
                    format!(
                        "UTXO not available for locking: {}:{}",
                        hex::encode(&txid),
                        vout
                    )
                    .into(),
                ));
            }
        }

        tx.commit()?;
        Ok(())
    })
    .await?;

    info!("Locked {} UTXOs", outpoints.len());
    Ok(())
}

pub async fn unlock_utxos(conn: &Connection, outpoints: &[OutPoint]) -> Result<()> {
    let params: Vec<(Vec<u8>, u32)> = outpoints
        .iter()
        .map(|op| (op.txid.as_byte_array().to_vec(), op.vout))
        .collect();

    conn.call(move |conn| {
        let tx = conn.transaction()?;

        for (txid, vout) in params {
            tx.execute(
                r#"
                UPDATE utxos 
                SET is_locked = 0, locked_at = NULL
                WHERE txid = ?1 AND vout = ?2
                "#,
                params![txid, vout],
            )?;
        }

        tx.commit()?;
        Ok(())
    })
    .await?;

    info!("Unlocked {} UTXOs", outpoints.len());
    Ok(())
}

pub async fn get_available_utxos(conn: &Connection, min_confirmations: u32) -> Result<Vec<DbUtxo>> {
    let utxos = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                r#"
            SELECT txid, vout, value_sats, script_pubkey, confirmations, created_at
            FROM utxos
            WHERE is_locked = 0 AND is_spent = 0 AND confirmations >= ?1
            ORDER BY value_sats ASC, confirmations DESC
            "#,
            )?;

            let rows = stmt.query_map(params![min_confirmations], |row| {
                let txid_bytes: Vec<u8> = row.get(0)?;
                let vout: u32 = row.get(1)?;
                let value_sats: i64 = row.get(2)?;
                let script_bytes: Vec<u8> = row.get(3)?;
                let confirmations: i64 = row.get(4)?;
                let created_at: i64 = row.get(5)?;

                Ok((
                    txid_bytes,
                    vout,
                    value_sats,
                    script_bytes,
                    confirmations,
                    created_at,
                ))
            })?;

            let mut utxos = Vec::new();
            for row in rows {
                let (txid_bytes, vout, value_sats, script_bytes, confirmations, created_at) = row?;

                let txid = Txid::from_slice(&txid_bytes)
                    .map_err(|_| tokio_rusqlite::Error::Other("Invalid txid".into()))?;

                let script_pubkey = ScriptBuf::from(script_bytes);

                utxos.push(DbUtxo {
                    outpoint: OutPoint::new(txid, vout),
                    value: Amount::from_sat(value_sats as u64),
                    script_pubkey,
                    confirmations: confirmations as u32,
                    is_locked: false,
                    is_spent: false,
                    created_at: created_at as u64,
                    locked_at: None,
                    spending_txid: None,
                });
            }

            Ok(utxos)
        })
        .await?;

    Ok(utxos)
}

pub async fn update_utxo_confirmations(
    conn: &Connection,
    updates: &[(OutPoint, u32)],
) -> Result<()> {
    let params: Vec<(Vec<u8>, u32, u32)> = updates
        .iter()
        .map(|(op, confs)| (op.txid.as_byte_array().to_vec(), op.vout, *confs))
        .collect();

    conn.call(move |conn| {
        let tx = conn.transaction()?;

        for (txid, vout, confirmations) in params {
            tx.execute(
                r#"
                UPDATE utxos 
                SET confirmations = ?3
                WHERE txid = ?1 AND vout = ?2
                "#,
                params![txid, vout, confirmations],
            )?;
        }

        tx.commit()?;
        Ok(())
    })
    .await?;

    Ok(())
}

pub async fn mark_utxos_spent(
    conn: &Connection,
    spent_utxos: &[(OutPoint, Txid)],
    current_time: u64,
) -> Result<()> {
    let params: Vec<(Vec<u8>, u32, Vec<u8>)> = spent_utxos
        .iter()
        .map(|(op, spending_txid)| {
            (
                op.txid.as_byte_array().to_vec(),
                op.vout,
                spending_txid.as_byte_array().to_vec(),
            )
        })
        .collect();

    conn.call(move |conn| {
        let tx = conn.transaction()?;

        for (txid, vout, spending_txid) in params {
            tx.execute(
                r#"
                UPDATE utxos 
                SET is_spent = 1, spent_at = ?3, spending_txid = ?4, is_locked = 0, locked_at = NULL
                WHERE txid = ?1 AND vout = ?2
                "#,
                params![txid, vout, current_time as i64, spending_txid],
            )?;
        }

        tx.commit()?;
        Ok(())
    })
    .await?;

    info!("Marked {} UTXOs as spent", spent_utxos.len());
    Ok(())
}

pub async fn add_broadcasted_transaction(
    conn: &Connection,
    tx: &bitcoin::Transaction,
    fee: Amount,
    fee_rate_sat_vb: f64,
    replaces: Option<Txid>,
    current_time: u64,
) -> Result<()> {
    use bitcoin::consensus::encode::Encodable;

    let txid = tx.compute_txid();
    let mut raw_tx = Vec::new();
    tx.consensus_encode(&mut raw_tx)?;

    let txid_bytes = txid.as_byte_array().to_vec();
    let replaces_bytes = replaces.map(|t| t.as_byte_array().to_vec());
    let weight = tx.weight().to_wu() as i64;
    let num_inputs = tx.input.len() as i64;
    let num_outputs = tx.output.len() as i64;
    let fee_sats = fee.to_sat() as i64;

    conn.call(move |conn| {
        conn.execute(
            r#"
            INSERT INTO broadcasted_txs (
                txid, raw_tx, fee_sats, fee_rate_sat_vb, 
                is_rbf_enabled, replaces_txid,
                broadcasted_at, last_checked_at,
                num_inputs, num_outputs, weight
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                txid_bytes,
                raw_tx,
                fee_sats,
                fee_rate_sat_vb,
                1, // RBF on
                replaces_bytes,
                current_time as i64,
                current_time as i64,
                num_inputs,
                num_outputs,
                weight
            ],
        )?;
        Ok(())
    })
    .await?;

    info!("Added broadcasted transaction: {}", txid);
    Ok(())
}

/// Add parent-child relationships for CPFP tracking
pub async fn add_tx_relationships(
    conn: &Connection,
    relationships: &[(Txid, Txid, usize)], // (parent, child, input_index)
) -> Result<()> {
    let params: Vec<(Vec<u8>, Vec<u8>, usize)> = relationships
        .iter()
        .map(|(parent, child, idx)| {
            (
                parent.as_byte_array().to_vec(),
                child.as_byte_array().to_vec(),
                *idx,
            )
        })
        .collect();

    conn.call(move |conn| {
        let tx = conn.transaction()?;

        for (parent_txid, child_txid, input_idx) in params {
            tx.execute(
                r#"
                INSERT OR IGNORE INTO tx_relationships (
                    parent_txid, child_txid, child_input_idx
                ) VALUES (?1, ?2, ?3)
                "#,
                params![parent_txid, child_txid, input_idx as i64],
            )?;
        }

        tx.commit()?;
        Ok(())
    })
    .await?;

    info!("Added {} transaction relationships", relationships.len());
    Ok(())
}

/// Get all unconfirmed transactions up to a certain age
pub async fn get_unconfirmed_transactions(
    conn: &Connection,
    max_age_seconds: u64,
) -> Result<Vec<DbTransaction>> {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let min_time = current_time - max_age_seconds;

    conn.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT txid, raw_tx, fee_sats, fee_rate_sat_vb, confirmation_block, 
                    confirmations, is_rbf_enabled, replaced_by, broadcasted_at, last_checked
             FROM broadcasted_txs 
             WHERE confirmation_block IS NULL 
               AND replaced_by IS NULL
               AND broadcasted_at >= ?1
             ORDER BY broadcasted_at DESC",
        )?;

        let rows = stmt.query_map([min_time as i64], |row| {
            let txid_bytes: Vec<u8> = row.get(0)?;
            let raw_tx: Vec<u8> = row.get(1)?;
            let fee_sats: i64 = row.get(2)?;
            let fee_rate_sat_vb: f64 = row.get(3)?;
            let confirmation_block: Option<i64> = row.get(4)?;
            let confirmations: i64 = row.get(5)?;
            let is_rbf_enabled: i64 = row.get(6)?;
            let replaced_by_bytes: Option<Vec<u8>> = row.get(7)?;
            let broadcasted_at: i64 = row.get(8)?;
            let last_checked: i64 = row.get(9)?;

            Ok((
                txid_bytes,
                raw_tx,
                fee_sats,
                fee_rate_sat_vb,
                confirmation_block,
                confirmations,
                is_rbf_enabled != 0,
                replaced_by_bytes,
                broadcasted_at,
                last_checked,
            ))
        })?;

        let mut txs = Vec::new();
        for row in rows {
            let (
                txid_bytes,
                raw_tx,
                fee_sats,
                fee_rate_sat_vb,
                confirmation_block,
                confirmations,
                is_rbf_enabled,
                replaced_by_bytes,
                broadcasted_at,
                last_checked,
            ) = row?;

            let txid = Txid::from_slice(&txid_bytes)
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid txid".into()))?;

            let replaced_by = replaced_by_bytes
                .map(|bytes| Txid::from_slice(&bytes))
                .transpose()
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid replaced_by txid".into()))?;

            txs.push(DbTransaction {
                txid,
                raw_tx,
                fee: Amount::from_sat(fee_sats as u64),
                fee_rate_sat_vb,
                confirmation_block,
                confirmations,
                is_rbf_enabled,
                replaced_by,
                broadcasted_at: broadcasted_at as u64,
                last_checked: last_checked as u64,
            });
        }

        Ok(txs)
    })
    .await
    .map_err(|e| eyre::eyre!("Failed to get unconfirmed transactions: {}", e))
}

pub async fn update_tx_last_checked(conn: &Connection, txid: Txid, timestamp: u64) -> Result<()> {
    let txid_bytes = txid.as_byte_array().to_vec();

    conn.call(move |conn| {
        conn.execute(
            "UPDATE broadcasted_txs SET last_checked = ?1 WHERE txid = ?2",
            (timestamp as i64, txid_bytes),
        )?;
        Ok(())
    })
    .await
    .map_err(|e| eyre::eyre!("Failed to update last_checked: {}", e))
}

/// Mark a transaction as replaced by another transaction RBF
pub async fn mark_tx_replaced(
    conn: &Connection,
    replaced_txid: Txid,
    replacing_txid: Txid,
) -> Result<()> {
    let replaced_bytes = replaced_txid.as_byte_array().to_vec();
    let replacing_bytes = replacing_txid.as_byte_array().to_vec();

    conn.call(move |conn| {
        conn.execute(
            r#"
            UPDATE broadcasted_txs 
            SET replaced_by_txid = ?2
            WHERE txid = ?1
            "#,
            params![replaced_bytes, replacing_bytes],
        )?;
        Ok(())
    })
    .await?;

    info!(
        "Marked transaction {} as replaced by {}",
        replaced_txid, replacing_txid
    );
    Ok(())
}

/// Update transaction confirmations and block height
pub async fn update_tx_confirmations(
    conn: &Connection,
    txid: Txid,
    confirmations: i64,
    block_height: Option<i64>,
) -> Result<()> {
    let txid_bytes = txid.as_byte_array().to_vec();

    conn.call(move |conn| {
        conn.execute(
            r#"
            UPDATE broadcasted_txs 
            SET confirmations = ?2, confirmation_block = ?3
            WHERE txid = ?1
            "#,
            params![txid_bytes, confirmations, block_height],
        )?;
        Ok(())
    })
    .await?;

    debug!(
        "Updated transaction {} confirmations to {} (block: {:?})",
        txid, confirmations, block_height
    );
    Ok(())
}

/// Update RBF attempt count and timestamp
pub async fn update_rbf_attempt(conn: &Connection, txid: Txid, timestamp: u64) -> Result<()> {
    let txid_bytes = txid.as_byte_array().to_vec();

    conn.call(move |conn| {
        conn.execute(
            r#"
            UPDATE broadcasted_txs 
            SET rbf_attempt_count = rbf_attempt_count + 1,
                last_rbf_attempt = ?2
            WHERE txid = ?1
            "#,
            params![txid_bytes, timestamp as i64],
        )?;
        Ok(())
    })
    .await?;

    debug!("Updated RBF attempt for transaction {}", txid);
    Ok(())
}

pub async fn get_rbf_attempt_info(
    conn: &Connection,
    txid: Txid,
) -> Result<Option<(u8, Option<u64>)>> {
    let txid_bytes = txid.as_byte_array().to_vec();

    conn.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT rbf_attempt_count, last_rbf_attempt FROM broadcasted_txs WHERE txid = ?1",
        )?;

        match stmt.query_row([txid_bytes], |row| {
            let attempt_count: i64 = row.get(0)?;
            let last_attempt: Option<i64> = row.get(1)?;
            Ok((attempt_count as u8, last_attempt.map(|t| t as u64)))
        }) {
            Ok(info) => Ok(Some(info)),
            Err(e) if e.to_string().contains("no rows") => Ok(None),
            Err(e) => Err(e.into()),
        }
    })
    .await
    .map_err(|e| eyre::eyre!("Failed to get RBF attempt info: {}", e))
}

/// Get all currently locked UTXOs
pub async fn get_locked_utxos(conn: &Connection) -> Result<Vec<DbUtxo>> {
    conn.call(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT txid, vout, value_sats, script_pubkey, confirmations, created_at, locked_at
            FROM utxos
            WHERE is_locked = 1 AND is_spent = 0
            ORDER BY locked_at DESC
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            let txid_bytes: Vec<u8> = row.get(0)?;
            let vout: u32 = row.get(1)?;
            let value_sats: i64 = row.get(2)?;
            let script_bytes: Vec<u8> = row.get(3)?;
            let confirmations: i64 = row.get(4)?;
            let created_at: i64 = row.get(5)?;
            let locked_at: Option<i64> = row.get(6)?;

            Ok((
                txid_bytes,
                vout,
                value_sats,
                script_bytes,
                confirmations,
                created_at,
                locked_at,
            ))
        })?;

        let mut utxos = Vec::new();
        for row in rows {
            let (txid_bytes, vout, value_sats, script_bytes, confirmations, created_at, locked_at) =
                row?;

            let txid = Txid::from_slice(&txid_bytes)
                .map_err(|_| tokio_rusqlite::Error::Other("Invalid txid".into()))?;

            let script_pubkey = ScriptBuf::from(script_bytes);

            utxos.push(DbUtxo {
                outpoint: OutPoint::new(txid, vout),
                value: Amount::from_sat(value_sats as u64),
                script_pubkey,
                confirmations: confirmations as u32,
                is_locked: true,
                is_spent: false,
                created_at: created_at as u64,
                locked_at: locked_at.map(|t| t as u64),
                spending_txid: None,
            });
        }

        Ok(utxos)
    })
    .await
    .map_err(|e| eyre::eyre!("Failed to get locked UTXOs: {}", e))
}
