//! Block watcher for the Bitcoin transaction broadcaster
//!
//! This module monitors new blocks and updates UTXO/transaction confirmations,
//! removes spent UTXOs after threshold, and updates transaction confirmations.

use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::Txid;
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::{bitcoin, RpcApi};
use tokio::sync::{broadcast, Mutex};
use tokio_rusqlite::{params, Connection};
use tracing::{debug, error, info, warn};

use crate::bitcoin_utils::AsyncBitcoinClient;
use crate::btc_txn_broadcaster_db::{get_unconfirmed_transactions, update_tx_confirmations};
use crate::utxo_manager::UtxoManager;

/// Special marker for UTXOs spent by unknown transactions
const UNKNOWN_SPENDING_TX: [u8; 32] = [0xFF; 32];

#[derive(Debug, Clone)]
pub struct BlockWatcherConfig {
    /// Confirmations needed before removing spent UTXOs
    pub spent_removal_confirmations: u32,
    /// Whether to remove confirmed transactions from database
    pub remove_confirmed_transactions: bool,
    /// Confirmation threshold for considering transactions fully confirmed
    pub confirmation_threshold: u32,
    /// Maximum age for tracking unconfirmed transactions (in seconds)
    pub max_transaction_age: u64,
}

impl Default for BlockWatcherConfig {
    fn default() -> Self {
        Self {
            spent_removal_confirmations: 6,
            remove_confirmed_transactions: false,
            confirmation_threshold: 6,
            max_transaction_age: 7 * 24 * 60 * 60, // 7 days
        }
    }
}

pub struct BlockWatcher {
    db_conn: Arc<Mutex<Connection>>,
    utxo_manager: Arc<UtxoManager>,
    btc_rpc: Arc<AsyncBitcoinClient>,
    config: BlockWatcherConfig,
}

impl BlockWatcher {
    pub fn new(
        db_conn: Arc<Mutex<Connection>>,
        utxo_manager: Arc<UtxoManager>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        config: BlockWatcherConfig,
    ) -> Self {
        Self {
            db_conn,
            utxo_manager,
            btc_rpc,
            config,
        }
    }

    pub async fn start_with_subscription(
        self: Arc<Self>,
        mut block_subscription: broadcast::Receiver<BlockLeaf>,
    ) -> eyre::Result<()> {
        info!("Starting block watcher with subscription");

        // Process current state on startup
        match self.btc_rpc.get_block_count().await {
            Ok(block_count) => {
                let current_height = block_count as u32;
                info!(
                    "Processing current blockchain state at height {}",
                    current_height
                );

                if let Err(e) = self.process_block(current_height).await {
                    warn!("Failed to process current state: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to get current block height: {}", e);
            }
        }

        loop {
            match block_subscription.recv().await {
                Ok(block_leaf) => {
                    info!(
                        "New block received: height={}, hash={}",
                        block_leaf.height,
                        hex::encode(block_leaf.block_hash)
                    );

                    if let Err(e) = self.process_block(block_leaf.height).await {
                        error!(
                            "Failed to process block at height {}: {}",
                            block_leaf.height, e
                        );
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!("Block watcher lagged, skipped {} blocks", skipped);
                    // Get current state and process
                    match self.btc_rpc.get_block_count().await {
                        Ok(block_count) => {
                            let current_height = block_count as u32;
                            if let Err(e) = self.process_block(current_height).await {
                                warn!("Failed to catch up after lag: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to get block count after lag: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Block subscription error: {}", e);
                    return Err(eyre::eyre!("Block subscription terminated: {}", e));
                }
            }
        }
    }

    async fn process_block(&self, block_height: u32) -> eyre::Result<()> {
        debug!("Processing block at height {}", block_height);

        // Update UTXO confirmations
        self.update_utxo_confirmations(block_height).await?;

        // Update transaction confirmations
        self.update_transaction_confirmations(block_height).await?;

        // Clean up spent UTXOs
        self.cleanup_spent_utxos().await?;

        Ok(())
    }

    async fn update_utxo_confirmations(&self, current_height: u32) -> eyre::Result<()> {
        // Get all UTXOs that need confirmation updates
        let utxos_to_update = {
            let conn = self.db_conn.lock().await;
            conn.call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT txid, vout, confirmations FROM utxos 
                     WHERE confirmations < ?1 AND is_spent = 0",
                )?;

                let results = stmt
                    .query_map([current_height], |row| {
                        let txid_bytes: Vec<u8> = row.get(0)?;
                        let vout: u32 = row.get(1)?;
                        let current_confs: i64 = row.get(2)?;

                        Ok((txid_bytes, vout, current_confs))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(results)
            })
            .await?
        };

        if utxos_to_update.is_empty() {
            return Ok(());
        }

        debug!("Updating confirmations for {} UTXOs", utxos_to_update.len());

        // Group UTXOs by transaction for batch processing
        let mut txid_to_utxos: std::collections::HashMap<Txid, Vec<(u32, i64)>> =
            std::collections::HashMap::new();

        for (txid_bytes, vout, current_confs) in utxos_to_update {
            let txid = Txid::from_slice(&txid_bytes)?;
            txid_to_utxos
                .entry(txid)
                .or_default()
                .push((vout, current_confs));
        }

        // Batch process transactions
        const BATCH_SIZE: usize = 10;
        let txids: Vec<Txid> = txid_to_utxos.keys().cloned().collect();

        for chunk in txids.chunks(BATCH_SIZE) {
            let mut updates = Vec::new();
            let mut spent_utxos = Vec::new();

            // Process each transaction in the chunk
            for &txid in chunk {
                match self.btc_rpc.get_raw_transaction_info(&txid, None).await {
                    Ok(tx_info) => {
                        let confirmations = tx_info.confirmations.unwrap_or(0) as u32;

                        // Update all UTXOs for this transaction
                        if let Some(utxos) = txid_to_utxos.get(&txid) {
                            for &(vout, _) in utxos {
                                let outpoint = bitcoin::OutPoint::new(txid, vout);
                                updates.push((outpoint, confirmations));
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to get transaction info for {}: {}", txid, e);
                        // Transaction might be dropped from mempool
                        if e.to_string().contains("not found") {
                            warn!(
                                "Transaction {} not found, marking associated UTXOs for removal",
                                txid
                            );
                            if let Some(utxos) = txid_to_utxos.get(&txid) {
                                for &(vout, _) in utxos {
                                    // Use special marker for unknown spending transaction
                                    spent_utxos.push((
                                        bitcoin::OutPoint::new(txid, vout),
                                        UNKNOWN_SPENDING_TX,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // Batch update confirmations
            if !updates.is_empty() {
                self.utxo_manager.update_confirmations(&updates).await?;
            }

            // Batch mark as spent (for dropped transactions)
            if !spent_utxos.is_empty() {
                // Convert the marker to Txid for the mark_spent call
                let spent_with_txid: Vec<(bitcoin::OutPoint, Txid)> = spent_utxos
                    .into_iter()
                    .map(|(op, marker)| (op, Txid::from_slice(&marker).unwrap()))
                    .collect();
                self.utxo_manager.mark_spent(&spent_with_txid).await?;
            }
        }

        Ok(())
    }

    async fn update_transaction_confirmations(&self, current_height: u32) -> eyre::Result<()> {
        // Get unconfirmed transactions
        let unconfirmed_txs = {
            let conn = self.db_conn.lock().await;
            get_unconfirmed_transactions(&*conn, self.config.max_transaction_age).await?
        };

        if unconfirmed_txs.is_empty() {
            return Ok(());
        }

        debug!(
            "Updating confirmations for {} transactions",
            unconfirmed_txs.len()
        );

        // Update each transaction
        for tx_info in unconfirmed_txs {
            match self
                .btc_rpc
                .get_raw_transaction_info(&tx_info.txid, None)
                .await
            {
                Ok(rpc_tx_info) => {
                    let confirmations = rpc_tx_info.confirmations.unwrap_or(0);
                    let block_height = if confirmations > 0 && rpc_tx_info.blockhash.is_some() {
                        Some((current_height - confirmations as u32 + 1) as i64)
                    } else {
                        None
                    };

                    // Update transaction in database
                    {
                        let conn = self.db_conn.lock().await;
                        update_tx_confirmations(
                            &*conn,
                            tx_info.txid,
                            confirmations as i64,
                            block_height,
                        )
                        .await?;
                    }

                    if confirmations >= self.config.confirmation_threshold {
                        info!(
                            "Transaction {} is fully confirmed with {} confirmations",
                            tx_info.txid, confirmations
                        );
                    }
                }
                Err(e) => {
                    debug!("Failed to get transaction info for {}: {}", tx_info.txid, e);

                    // Check if transaction was replaced (RBF)
                    if e.to_string().contains("not found") && tx_info.is_rbf_enabled {
                        warn!(
                            "RBF transaction {} not found in mempool or blockchain",
                            tx_info.txid
                        );
                        // Transaction was likely replaced so needa be marked by RBF handler
                    }
                }
            }
        }

        Ok(())
    }

    async fn cleanup_spent_utxos(&self) -> eyre::Result<()> {
        let spent_utxos = {
            let conn = self.db_conn.lock().await;
            let spent_removal_confs = self.config.spent_removal_confirmations;

            conn.call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT txid, vout FROM utxos 
                     WHERE is_spent = 1 AND confirmations >= ?1",
                )?;

                let results = stmt
                    .query_map([spent_removal_confs], |row| {
                        let txid_bytes: Vec<u8> = row.get(0)?;
                        let vout: u32 = row.get(1)?;
                        Ok((txid_bytes, vout))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(results)
            })
            .await?
        };

        if !spent_utxos.is_empty() {
            info!(
                "Removing {} spent UTXOs with >= {} confirmations",
                spent_utxos.len(),
                self.config.spent_removal_confirmations
            );

            // Remove spent UTXOs
            {
                let conn = self.db_conn.lock().await;
                conn.call(move |conn| {
                    let tx = conn.transaction()?;

                    for (txid_bytes, vout) in spent_utxos {
                        tx.execute(
                            "DELETE FROM utxos WHERE txid = ?1 AND vout = ?2",
                            params![txid_bytes, vout],
                        )?;
                    }

                    tx.commit()?;
                    Ok(())
                })
                .await?;
            }
        }

        Ok(())
    }

    pub async fn get_sync_status(&self) -> eyre::Result<SyncStatus> {
        let current_height = self.btc_rpc.get_block_count().await? as u32;

        let (unconfirmed_utxo_count, total_utxo_count) = {
            let conn = self.db_conn.lock().await;
            conn.call(|conn| {
                let unconfirmed: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM utxos WHERE confirmations = 0 AND is_spent = 0",
                    [],
                    |row| row.get(0),
                )?;

                let total: i64 =
                    conn.query_row("SELECT COUNT(*) FROM utxos WHERE is_spent = 0", [], |row| {
                        row.get(0)
                    })?;

                Ok((unconfirmed as u32, total as u32))
            })
            .await?
        };

        let unconfirmed_tx_count = {
            let conn = self.db_conn.lock().await;
            conn.call(|conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM broadcasted_txs WHERE confirmations = 0",
                    [],
                    |row| row.get(0),
                )?;
                Ok(count as u32)
            })
            .await?
        };

        Ok(SyncStatus {
            current_block_height: current_height,
            unconfirmed_utxo_count,
            total_utxo_count,
            unconfirmed_transaction_count: unconfirmed_tx_count,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub current_block_height: u32,
    pub unconfirmed_utxo_count: u32,
    pub total_utxo_count: u32,
    pub unconfirmed_transaction_count: u32,
}
