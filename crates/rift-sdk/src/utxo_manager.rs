//! UTXO Manager for the Bitcoin Transaction Broadcaster
//!
//! This module provides a interface for managing UTXOs,
//! including selection, locking, and tracking.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use bitcoin_coin_selection::{self as cs};
use eyre::Result;
use tokio::sync::Mutex;
use tokio_rusqlite::Connection;
use tracing::{debug, info, warn};

use crate::btc_txn_broadcaster::{InputUtxo, CHANGE_OUTPUT_W};
use crate::btc_txn_broadcaster_db::{
    self as db, add_utxo, get_available_utxos, lock_utxos, mark_utxos_spent, unlock_utxos,
    update_utxo_confirmations, DbUtxo,
};
use crate::DatabaseLocation;

/// Special marker for UTXOs spent by unknown transactions
/// Uses all 0xFF bytes to distinguish from real transaction IDs
const UNKNOWN_SPENDING_TX: [u8; 32] = [0xFF; 32];

#[derive(Debug, Clone)]
pub struct UtxoManagerConfig {
    /// Minimum confirmations required for spending
    pub min_confirmations: u32,
    /// Maximum age (in seconds) for locked UTXOs before auto-unlock
    pub max_lock_time_seconds: u64,
    /// Target confirmations before removing spent UTXOs from tracking
    pub spent_removal_confirmations: u32,
}

impl Default for UtxoManagerConfig {
    fn default() -> Self {
        Self {
            min_confirmations: 0,           // Allow spending unconfirmed by default
            max_lock_time_seconds: 600,     // 10 minutes
            spent_removal_confirmations: 6, // Remove after 6 confirmations
        }
    }
}

pub struct UtxoManager {
    conn: Arc<Mutex<Connection>>,
    config: UtxoManagerConfig,
    wallet_script_pubkey: ScriptBuf,
    wallet_address: bitcoin::Address<bitcoin::address::NetworkChecked>,
}

impl UtxoManager {
    pub async fn new(
        db_location: DatabaseLocation,
        config: UtxoManagerConfig,
        wallet_script_pubkey: ScriptBuf,
        wallet_address: bitcoin::Address<bitcoin::address::NetworkChecked>,
    ) -> Result<Self> {
        let conn = match db_location {
            DatabaseLocation::InMemory => Connection::open_in_memory().await?,
            DatabaseLocation::Directory(path) => {
                let db_path = format!("{}/btc_broadcaster.db", path);
                Connection::open(&db_path).await?
            }
        };

        db::setup_broadcaster_database(&conn).await?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            config,
            wallet_script_pubkey,
            wallet_address,
        })
    }

    /// Check if a transaction ID represents an unknown spending transaction
    pub fn is_unknown_spending_tx(txid: &Txid) -> bool {
        txid == &Txid::from_slice(&UNKNOWN_SPENDING_TX).unwrap()
    }

    pub async fn get_connection(&self) -> Result<tokio::sync::MutexGuard<'_, Connection>> {
        Ok(self.conn.lock().await)
    }

    pub async fn get_shared_connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    pub fn get_address(&self) -> bitcoin::Address<bitcoin::address::NetworkChecked> {
        self.wallet_address.clone()
    }

    pub async fn add_new_utxo(
        &self,
        outpoint: OutPoint,
        value: Amount,
        script_pubkey: ScriptBuf,
    ) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let conn = self.conn.lock().await;

        add_utxo(&*conn, outpoint, value, script_pubkey, current_time).await?;

        info!(
            "Added new UTXO: {}:{} with value {} sats",
            outpoint.txid,
            outpoint.vout,
            value.to_sat()
        );

        Ok(())
    }

    pub async fn select_and_lock_utxos(
        &self,
        target_value: Amount,
        fee_rate: bitcoin::FeeRate,
        long_term_fee_rate: bitcoin::FeeRate,
    ) -> Result<(Vec<InputUtxo>, Option<Amount>)> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let conn = self.conn.lock().await;

        // Clean up any stale locks
        self.cleanup_stale_locks(&*conn, current_time).await?;

        // Get available UTXOs
        let db_utxos = get_available_utxos(&*conn, self.config.min_confirmations).await?;

        if db_utxos.is_empty() {
            return Err(eyre::eyre!("No available UTXOs"));
        }

        // Convert to InputUtxo for coin selection
        let available_utxos: Vec<InputUtxo> = db_utxos
            .iter()
            .map(|u| InputUtxo::new(u.outpoint, u.value))
            .collect();

        // Run coin selection
        let cost_of_change = bitcoin::transaction::effective_value(
            fee_rate,
            CHANGE_OUTPUT_W,
            Amount::from_sat(50_000), // dust threshold
        )
        .unwrap_or(Amount::from_sat(1000).to_signed().unwrap())
        .to_unsigned()
        .unwrap_or(Amount::from_sat(1000));

        let (.., selected_refs) = cs::select_coins(
            target_value,
            cost_of_change,
            fee_rate,
            long_term_fee_rate,
            &available_utxos,
        )
        .ok_or_else(|| eyre::eyre!("Insufficient funds for target value"))?;

        // Convert selected references to owned UTXOs
        let selected_utxos: Vec<InputUtxo> = selected_refs.iter().map(|&u| u.clone()).collect();

        // Lock the selected UTXOs
        let outpoints: Vec<OutPoint> = selected_utxos.iter().map(|u| u.outpoint).collect();

        lock_utxos(&*conn, &outpoints, current_time).await?;

        // Calculate if change is needed
        let change_amount =
            crate::btc_txn_broadcaster::calc_change(&selected_refs, target_value, fee_rate)?;

        info!(
            "Selected {} UTXOs for {} sats, change: {:?}",
            selected_utxos.len(),
            target_value.to_sat(),
            change_amount.map(|a| a.to_sat())
        );

        Ok((selected_utxos, change_amount))
    }

    pub async fn unlock_utxos_by_outpoints(&self, outpoints: &[OutPoint]) -> Result<()> {
        let conn = self.conn.lock().await;
        unlock_utxos(&*conn, outpoints).await?;

        info!("Unlocked {} UTXOs", outpoints.len());
        Ok(())
    }

    pub async fn mark_spent(&self, spent_pairs: &[(OutPoint, Txid)]) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let conn = self.conn.lock().await;

        mark_utxos_spent(&*conn, spent_pairs, current_time).await?;

        info!("Marked {} UTXOs as spent", spent_pairs.len());

        Ok(())
    }

    pub async fn update_confirmations(&self, updates: &[(OutPoint, u32)]) -> Result<()> {
        let conn = self.conn.lock().await;
        update_utxo_confirmations(&*conn, updates).await?;

        debug!("Updated confirmations for {} UTXOs", updates.len());
        Ok(())
    }

    pub async fn get_balance(&self) -> Result<(Amount, Amount)> {
        let conn = self.conn.lock().await;

        // Get all UTXOs (including unconfirmed)
        let all_utxos = get_available_utxos(&*conn, 0).await?;
        let confirmed_utxos = get_available_utxos(&*conn, self.config.min_confirmations).await?;

        let total_balance: Amount = all_utxos.iter().map(|u| u.value).sum();
        let confirmed_balance: Amount = confirmed_utxos.iter().map(|u| u.value).sum();

        Ok((total_balance, confirmed_balance))
    }

    pub async fn can_fund_outputs(&self, outputs: &[bitcoin::TxOut]) -> Result<bool> {
        let target_value: Amount = outputs.iter().map(|o| o.value).sum();

        // Estimate fee based on typical transaction size
        // Assume 1 input for each 0.01 BTC needed
        let estimated_inputs = ((target_value.to_sat() / 1_000_000) + 1).max(1);
        // P2WPKH: ~68 vbytes per input, ~31 vbytes per output, ~10 vbytes overhead
        let estimated_vbytes = (estimated_inputs * 68) + (outputs.len() as u64 * 31) + 10;
        // Use 20 sat/vB for estimation
        let estimated_fee = Amount::from_sat(estimated_vbytes * 20);

        let required_amount = target_value + estimated_fee;

        let (total_balance, _) = self.get_balance().await?;

        Ok(total_balance >= required_amount)
    }

    pub async fn get_locked_utxos(&self) -> Result<Vec<DbUtxo>> {
        let conn = self.conn.lock().await;
        db::get_locked_utxos(&*conn).await
    }

    pub async fn sync_utxos_from_chain(&self, chain_utxos: &[esplora_client::Utxo]) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let conn = self.conn.lock().await;

        // Get all our tracked UTXOs
        let tracked_utxos = conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    r#"
                SELECT txid, vout, is_spent
                FROM utxos
                "#,
                )?;

                let rows = stmt.query_map([], |row| {
                    let txid_bytes: Vec<u8> = row.get(0)?;
                    let vout: u32 = row.get(1)?;
                    let is_spent: i64 = row.get(2)?;
                    Ok((txid_bytes, vout, is_spent != 0))
                })?;

                let mut result = Vec::new();
                for row in rows {
                    let (txid_bytes, vout, is_spent) = row?;
                    let txid = Txid::from_slice(&txid_bytes)
                        .map_err(|_| tokio_rusqlite::Error::Other("Invalid txid".into()))?;
                    result.push((OutPoint::new(txid, vout), is_spent));
                }
                Ok(result)
            })
            .await?;

        // Create lookup sets
        let tracked_outpoints: std::collections::HashSet<OutPoint> =
            tracked_utxos.iter().map(|(op, _)| *op).collect();

        let chain_outpoints: std::collections::HashSet<OutPoint> = chain_utxos
            .iter()
            .map(|u| OutPoint::new(u.txid, u.vout))
            .collect();

        // Find new UTXOs to add
        let mut new_count = 0;
        for utxo in chain_utxos {
            let outpoint = OutPoint::new(utxo.txid, utxo.vout);
            if !tracked_outpoints.contains(&outpoint) {
                // This is a new UTXO we should track
                add_utxo(
                    &*conn,
                    outpoint,
                    Amount::from_sat(utxo.value),
                    self.wallet_script_pubkey.clone(),
                    current_time,
                )
                .await?;
                new_count += 1;
            }
        }

        // Find spent UTXOs and their spending transactions
        let mut spent_pairs = Vec::new();

        // Get spending transactions from our broadcasted_txs table
        let spending_txids = conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT txid, raw_tx 
                    FROM broadcasted_txs 
                    WHERE is_confirmed = 0 OR confirmations < 100
                    ORDER BY broadcasted_at DESC
                    "#,
                )?;

                let rows = stmt.query_map([], |row| {
                    let txid_bytes: Vec<u8> = row.get(0)?;
                    let raw_tx: Vec<u8> = row.get(1)?;
                    Ok((txid_bytes, raw_tx))
                })?;

                let mut spending_map = std::collections::HashMap::new();
                for row in rows {
                    let (txid_bytes, raw_tx) = row?;
                    let txid = Txid::from_slice(&txid_bytes)
                        .map_err(|_| tokio_rusqlite::Error::Other("Invalid txid".into()))?;

                    // Deserialize transaction to check its inputs
                    use bitcoin::consensus::encode::Decodable;
                    if let Ok(tx) = bitcoin::Transaction::consensus_decode(&mut &raw_tx[..]) {
                        for input in tx.input.iter() {
                            spending_map.insert(input.previous_output, txid);
                        }
                    }
                }
                Ok(spending_map)
            })
            .await?;

        for (outpoint, is_already_spent) in &tracked_utxos {
            if !is_already_spent && !chain_outpoints.contains(outpoint) {
                // This UTXO is no longer in the chain, mark as spent
                let spending_txid = spending_txids.get(outpoint).copied().unwrap_or_else(|| {
                    // If we don't have it in our database, it was spent by an external transaction
                    debug!(
                        "UTXO {} spent by external transaction (not in our database)",
                        outpoint
                    );
                    // Use the constant marker for unknown spending transactions
                    Txid::from_slice(&UNKNOWN_SPENDING_TX).unwrap()
                });

                spent_pairs.push((*outpoint, spending_txid));
            }
        }

        if !spent_pairs.is_empty() {
            let known_count = spent_pairs
                .iter()
                .filter(|(_, txid)| *txid != Txid::from_slice(&UNKNOWN_SPENDING_TX).unwrap())
                .count();

            info!(
                "Marking {} UTXOs as spent ({} with known spending tx, {} by external txs)",
                spent_pairs.len(),
                known_count,
                spent_pairs.len() - known_count
            );
            mark_utxos_spent(&*conn, &spent_pairs, current_time).await?;
        }

        info!(
            "UTXO sync complete: {} new, {} spent",
            new_count,
            spent_pairs.len()
        );

        Ok(())
    }

    async fn cleanup_stale_locks(&self, conn: &Connection, current_time: u64) -> Result<()> {
        let cutoff_time = current_time - self.config.max_lock_time_seconds;

        let stale_count = conn
            .call(move |conn| {
                let count = conn.execute(
                    r#"
                UPDATE utxos 
                SET is_locked = 0, locked_at = NULL
                WHERE is_locked = 1 
                  AND is_spent = 0 
                  AND locked_at < ?1
                "#,
                    [cutoff_time as i64],
                )?;
                Ok(count)
            })
            .await?;

        if stale_count > 0 {
            warn!("Cleaned up {} stale UTXO locks", stale_count);
        }

        Ok(())
    }
}
