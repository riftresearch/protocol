use alloy::{
    primitives::Address,
    providers::Provider,
    pubsub::PubSubFrontend,
    rpc::types::{BlockNumberOrTag, Filter, Log},
    sol_types::SolEvent,
};
use bitcoin_light_client_core::{
    hasher::{Digest, Keccak256Hasher},
    leaves::{decompress_block_leaves, BlockLeaf},
};
use eyre::Result;
use futures_util::stream::StreamExt;
use rift_sdk::checkpoint_mmr::CheckpointedBlockTree;
use rift_sdk::DatabaseLocation;
use sol_bindings::{
    RiftExchange,
    Types::{DepositVault, VaultUpdateContext},
};
use tokio_util::task::{task_tracker, TaskTracker};

use core::panic;
use std::{path::PathBuf, str::FromStr, sync::Arc};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinSet,
};
use tracing::{info, info_span, instrument, warn, Instrument};

// Added for idempotency tracking.
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    db::{
        add_deposit, add_proposed_swap, get_deposits_for_recipient, get_otc_swap_by_deposit_id,
        get_proposed_swap_id, get_swaps_ready_to_be_released, get_virtual_swaps,
        setup_swaps_database, update_deposit_to_withdrawn, update_proposed_swap_to_released,
        ChainAwareProposedSwapWithDeposit,
    },
    models::{ChainAwareDeposit, ChainAwareProposedSwap},
};
use crate::{
    db::{get_deposit_by_id, get_oldest_active_deposit},
    models::OTCSwap,
};

pub struct ContractDataEngine {
    pub checkpointed_block_tree: Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
    pub swap_database_connection: Arc<tokio_rusqlite::Connection>,
    // New field to track if the event listener has been started already.
    server_started: Arc<AtomicBool>,
    initial_sync_complete_watcher: Arc<Mutex<Vec<tokio::sync::oneshot::Sender<bool>>>>,
    initial_sync_complete: Arc<AtomicBool>,
}

impl ContractDataEngine {
    /// Seeds the DataEngine with the provided checkpoint leaves, but does not start the event listener.
    pub async fn seed(
        database_location: &DatabaseLocation,
        checkpoint_leaves: Vec<BlockLeaf>,
    ) -> Result<Self> {
        let checkpointed_block_tree = Arc::new(RwLock::new(
            CheckpointedBlockTree::open(database_location).await?,
        ));
        let swap_database_connection = Arc::new(match database_location.clone() {
            DatabaseLocation::InMemory => tokio_rusqlite::Connection::open_in_memory().await?,
            DatabaseLocation::Directory(path) => {
                tokio_rusqlite::Connection::open(get_qualified_swaps_database_path(path)).await?
            }
        });

        setup_swaps_database(&swap_database_connection).await?;

        Self::conditionally_seed_mmr(&checkpointed_block_tree, checkpoint_leaves).await?;

        Ok(Self {
            checkpointed_block_tree,
            swap_database_connection,
            initial_sync_complete: Arc::new(AtomicBool::new(false)),
            initial_sync_complete_watcher: Arc::new(Mutex::new(Vec::new())),
            server_started: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn wait_for_initial_sync(&self) -> eyre::Result<()> {
        let mut initial_sync_complete_watcher = self.initial_sync_complete_watcher.lock().await;
        if self
            .initial_sync_complete
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        initial_sync_complete_watcher.push(tx);
        drop(initial_sync_complete_watcher);
        rx.await
            .map_err(|_| eyre::eyre!("Initial sync watcher channel closed unexpectedly"))?;
        Ok(())
    }

    /// Seeds the DataEngine and immediately starts the event listener.
    /// Internally this uses seed() and then start_server().
    pub async fn start(
        database_location: &DatabaseLocation,
        provider: Arc<dyn Provider<PubSubFrontend>>,
        rift_exchange_address: Address,
        deploy_block_number: u64,
        checkpoint_leaves: Vec<BlockLeaf>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<Self> {
        // Seed the engine with checkpoint leaves.
        let mut engine = Self::seed(database_location, checkpoint_leaves).await?;
        // Start event listener
        engine
            .start_event_listener(
                provider,
                rift_exchange_address,
                deploy_block_number,
                join_set,
            )
            .await?;

        Ok(engine)
    }

    /// Starts the event listener server by passing the remaining configuration.
    /// This method will only spawn the event listener once.
    pub async fn start_event_listener(
        &mut self,
        provider: Arc<dyn Provider<PubSubFrontend>>,
        rift_exchange_address: Address,
        deploy_block_number: u64,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> eyre::Result<()> {
        // If the server is already started, return an error.
        // TODO: Solve this via better struct design instead of using an actual server_started flag.
        if self.server_started.swap(true, Ordering::SeqCst) {
            return Err(eyre::eyre!("Server already started"));
        }

        let checkpointed_block_tree_clone = self.checkpointed_block_tree.clone();
        let swap_database_connection_clone = self.swap_database_connection.clone();
        let initial_sync_complete_clone = self.initial_sync_complete.clone();
        let initial_sync_complete_watcher_clone = self.initial_sync_complete_watcher.clone();

        join_set.spawn(
            async move {
                info!("Starting contract data engine event listener");
                listen_for_events(
                    provider,
                    &swap_database_connection_clone,
                    checkpointed_block_tree_clone,
                    rift_exchange_address,
                    deploy_block_number,
                    initial_sync_complete_clone,
                    initial_sync_complete_watcher_clone,
                )
                .await
            }
            .instrument(info_span!("CDE Event Listener")),
        );

        Ok(())
    }

    async fn conditionally_seed_mmr(
        checkpointed_block_tree: &Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
        checkpoint_leaves: Vec<BlockLeaf>,
    ) -> Result<()> {
        if checkpointed_block_tree
            .read()
            .await
            .get_leaf_count()
            .await?
            == 0
            && !checkpoint_leaves.is_empty()
        {
            checkpointed_block_tree
                .write()
                .await
                .create_seed_checkpoint(&checkpoint_leaves)
                .await?;

            println!("DataEngine seeded with checkpoint leaves.");
        }
        Ok(())
    }

    pub async fn get_deposits_for_recipient(
        &self,
        address: Address,
        deposit_block_cutoff: u64,
    ) -> Result<Vec<DepositVault>> {
        get_deposits_for_recipient(
            &self.swap_database_connection,
            address,
            deposit_block_cutoff,
        )
        .await
    }

    pub async fn get_virtual_swaps(
        &self,
        address: Address,
        page: u32,
        page_size: Option<u32>,
    ) -> Result<Vec<OTCSwap>> {
        let page_size = page_size.unwrap_or(50);
        get_virtual_swaps(&self.swap_database_connection, address, page, page_size).await
    }

    pub async fn get_oldest_active_deposit(
        &self,
        current_block_timestamp: u64,
    ) -> Result<Option<ChainAwareDeposit>> {
        get_oldest_active_deposit(&self.swap_database_connection, current_block_timestamp).await
    }

    pub async fn get_otc_swap_by_deposit_id(
        &self,
        deposit_id: [u8; 32],
    ) -> Result<Option<OTCSwap>> {
        get_otc_swap_by_deposit_id(&self.swap_database_connection, deposit_id).await
    }

    pub async fn get_swaps_ready_to_be_released(
        &self,
        current_block_timestamp: u64,
    ) -> Result<Vec<ChainAwareProposedSwapWithDeposit>> {
        get_swaps_ready_to_be_released(&self.swap_database_connection, current_block_timestamp)
            .await
    }

    // get's the tip of the MMR, and returns a proof of the tip
    pub async fn get_tip_proof(&self) -> Result<(BlockLeaf, Vec<Digest>, Vec<Digest>)> {
        let checkpointed_block_tree = self.checkpointed_block_tree.read().await;
        let leaves_count = checkpointed_block_tree.get_leaf_count().await?;
        let leaf_index = leaves_count - 1;
        let leaf = checkpointed_block_tree
            .get_leaf_by_leaf_index(leaf_index)
            .await?;
        match leaf {
            Some(leaf) => {
                let proof = checkpointed_block_tree
                    .get_circuit_proof(leaf_index, None)
                    .await?;
                let siblings = proof.siblings;
                let peaks = proof.peaks;
                Ok((leaf, siblings, peaks))
            }
            None => Err(eyre::eyre!("Leaf not found")),
        }
    }

    // Delegate method that provides read access to the mmr
    pub async fn get_leaf_count(&self) -> Result<usize> {
        let checkpointed_block_tree = self.checkpointed_block_tree.read().await;
        checkpointed_block_tree
            .get_leaf_count()
            .await
            .map_err(|e| eyre::eyre!(e))
    }

    pub async fn get_mmr_root(&self) -> Result<Digest> {
        let checkpointed_block_tree = self.checkpointed_block_tree.read().await;
        checkpointed_block_tree
            .get_root()
            .await
            .map_err(|e| eyre::eyre!(e))
    }

    pub async fn get_mmr_bagged_peak(&self) -> Result<Digest> {
        let checkpointed_block_tree = self.checkpointed_block_tree.read().await;
        checkpointed_block_tree
            .get_bagged_peak()
            .await
            .map_err(|e| eyre::eyre!(e))
    }

    pub async fn get_deposit_by_id(
        &self,
        deposit_id: [u8; 32],
    ) -> Result<Option<ChainAwareDeposit>> {
        get_deposit_by_id(&self.swap_database_connection, deposit_id).await
    }
}

fn get_qualified_swaps_database_path(database_location: String) -> String {
    let path = PathBuf::from(database_location);
    let swaps_db_path = path.join("swaps.db");
    swaps_db_path.to_str().expect("Invalid path").to_string()
}

// This will run indefinitely
pub async fn listen_for_events(
    provider: Arc<dyn Provider<PubSubFrontend>>,
    db_conn: &Arc<tokio_rusqlite::Connection>,
    checkpointed_block_tree: Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
    rift_exchange_address: Address,
    deploy_block_number: u64,
    initial_sync_complete: Arc<AtomicBool>,
    initial_sync_complete_watcher: Arc<Mutex<Vec<tokio::sync::oneshot::Sender<bool>>>>,
) -> Result<()> {
    // First, get the current block number
    let current_block = provider.get_block_number().await?;
    info!("Current block number: {}", current_block);

    // Create filter for historical logs from deploy_block_number to current_block (inclusive)
    let historical_filter = Filter::new()
        .address(rift_exchange_address)
        .from_block(BlockNumberOrTag::Number(deploy_block_number))
        .to_block(BlockNumberOrTag::Number(current_block));

    // Fetch all historical logs
    info!(
        "Fetching historical logs from block {} to {}",
        deploy_block_number, current_block
    );
    let historical_logs = provider.get_logs(&historical_filter).await?;

    // Process historical logs
    for log in historical_logs.iter() {
        process_log(log, db_conn, &checkpointed_block_tree).await?;
    }

    info!("Processed {} historical logs", historical_logs.len());

    // Get the latest block number again to ensure we don't miss any blocks
    // that might have been produced while processing historical logs
    let latest_block = provider.get_block_number().await?;
    info!(
        "Latest block after processing historical logs: {}",
        latest_block
    );

    // Check for any logs that might have been emitted during historical processing
    if latest_block > current_block {
        let gap_filter = Filter::new()
            .address(rift_exchange_address)
            .from_block(BlockNumberOrTag::Number(current_block + 1))
            .to_block(BlockNumberOrTag::Number(latest_block));

        let gap_logs = provider.get_logs(&gap_filter).await?;
        info!(
            "Found {} logs in the gap between {} and {}",
            gap_logs.len(),
            current_block + 1,
            latest_block
        );

        // Process gap logs
        for log in gap_logs {
            process_log(&log, db_conn, &checkpointed_block_tree).await?;
        }
    }
    // TODO: This can potentially drop blocks, update this to subscribe BEFORE pulling historical logs

    // Create subscription filter for new logs starting after the latest processed block
    let subscription_filter = Filter::new()
        .address(rift_exchange_address)
        .from_block(BlockNumberOrTag::Number(latest_block + 1));

    // Subscribe to new logs
    let sub = provider.subscribe_logs(&subscription_filter).await?;
    let mut stream = sub.into_stream();
    info!(
        "Subscribed to new logs starting from block {}",
        latest_block + 1
    );

    // Signal that the initial sync is complete
    initial_sync_complete.store(true, std::sync::atomic::Ordering::SeqCst);
    {
        let mut initial_sync_complete_watcher = initial_sync_complete_watcher.lock().await;
        for tx in initial_sync_complete_watcher.drain(..) {
            let _ = tx.send(true);
        }
    }

    // Now process the subscription stream
    while let Some(log) = stream.next().await {
        process_log(&log, db_conn, &checkpointed_block_tree).await?;
    }

    println!("Subscription stream closed");

    Ok(())
}

async fn process_log(
    log: &Log,
    db_conn: &Arc<tokio_rusqlite::Connection>,
    checkpointed_block_tree: &Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
) -> Result<()> {
    info!("Processing log: {:?}", log);

    // If there's no topic then that's a critical error.
    let topic = log
        .topic0()
        .ok_or_else(|| eyre::eyre!("No topic found in log"))?;

    match *topic {
        RiftExchange::VaultsUpdated::SIGNATURE_HASH => {
            info_span!("handle_vault_updated")
                .in_scope(|| handle_vault_updated_event(log, db_conn))
                .await?;
        }
        RiftExchange::SwapsUpdated::SIGNATURE_HASH => {
            info_span!("handle_swap_updated")
                .in_scope(|| handle_swap_updated_event(log, db_conn))
                .await?;
        }
        RiftExchange::BitcoinLightClientUpdated::SIGNATURE_HASH => {
            info_span!("handle_bitcoin_light_client_updated")
                .in_scope(|| {
                    handle_bitcoin_light_client_updated_event(log, checkpointed_block_tree.clone())
                })
                .await?;
        }
        _ => {
            warn!("Unknown event topic");
        }
    }

    Ok(())
}

async fn handle_vault_updated_event(
    log: &Log,
    db_conn: &Arc<tokio_rusqlite::Connection>,
) -> Result<()> {
    info!("Received VaultUpdated event...");

    // Propagate any decoding error.
    let decoded = RiftExchange::VaultsUpdated::decode_log(&log.inner, false)
        .map_err(|e| eyre::eyre!("Failed to decode VaultUpdated event: {:?}", e))?;

    let deposit_vaults = decoded.data.vaults;
    let log_txid = log
        .transaction_hash
        .ok_or_else(|| eyre::eyre!("Missing txid in VaultUpdated event"))?;
    let log_block_number = log
        .block_number
        .ok_or_else(|| eyre::eyre!("Missing block number in VaultUpdated event"))?;
    let log_block_hash = log
        .block_hash
        .ok_or_else(|| eyre::eyre!("Missing block hash in VaultUpdated event"))?;

    for deposit_vault in deposit_vaults {
        match decoded.data.context {
            0 /* VaultUpdateContext::Created */ => {
                add_deposit(
                    db_conn,
                    deposit_vault,
                    log_block_number,
                    log_block_hash.into(),
                    log_txid.into(),
                )
                .await
                .map_err(|e| eyre::eyre!("add_deposit failed: {:?}", e))?;
            }
            1 /* VaultUpdateContext::Withdraw */ => {
                update_deposit_to_withdrawn(
                    db_conn,
                    deposit_vault.salt.into(),
                    log_txid.into(),
                    log_block_number,
                    log_block_hash.into(),
                )
                .await
                .map_err(|e| eyre::eyre!("update_deposit_to_withdrawn failed: {:?}", e))?;
            }
            _ => {}
        }
    }

    Ok(())
}

async fn handle_swap_updated_event(
    log: &Log,
    db_conn: &Arc<tokio_rusqlite::Connection>,
) -> Result<()> {
    info!("Received SwapUpdated event");

    // Propagate any decoding error.
    let decoded = RiftExchange::SwapsUpdated::decode_log(&log.inner, false)
        .map_err(|e| eyre::eyre!("Failed to decode SwapUpdated event: {:?}", e))?;

    let log_txid = log
        .transaction_hash
        .ok_or_else(|| eyre::eyre!("Missing txid in SwapUpdated event"))?;
    let log_block_number = log
        .block_number
        .ok_or_else(|| eyre::eyre!("Missing block number in SwapUpdated event"))?;
    let log_block_hash = log
        .block_hash
        .ok_or_else(|| eyre::eyre!("Missing block hash in SwapUpdated event"))?;

    match decoded.data.context {
        0 /* SwapUpdateContext::Created */ => {
            for swap in decoded.data.swaps {
                info!(
                    "Received SwapUpdated event: proposed_swap_id = {:?}",
                    get_proposed_swap_id(&swap)
                );
                add_proposed_swap(
                    db_conn,
                    &swap,
                    log_block_number,
                    log_block_hash.into(),
                    log_txid.into(),
                )
                .await
                .map_err(|e| eyre::eyre!("add_proposed_swap failed: {:?}", e))?;
            }
        }
        1 /* SwapUpdateContext::Complete */ => {
            for swap in decoded.data.swaps {
                update_proposed_swap_to_released(
                    db_conn,
                    get_proposed_swap_id(&swap),
                    log_txid.into(),
                    log_block_number,
                    log_block_hash.into(),
                )
                .await
                .map_err(|e| eyre::eyre!("update_proposed_swap_to_released failed: {:?}", e))?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_bitcoin_light_client_updated_event(
    log: &Log,
    checkpointed_block_tree: Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
) -> Result<()> {
    info!("Received BitcoinLightClientUpdated event");

    // Propagate any decoding error.
    let decoded = RiftExchange::BitcoinLightClientUpdated::decode_log(&log.inner, false)
        .map_err(|e| eyre::eyre!("Failed to decode BitcoinLightClientUpdated event: {:?}", e))?;

    let block_tree_data = &decoded.data;
    let prior_mmr_root = block_tree_data.priorMmrRoot.0;
    let new_mmr_root = block_tree_data.newMmrRoot.0;
    let compressed_block_leaves = block_tree_data.compressedBlockLeaves.0.to_vec();
    let block_leaves = decompress_block_leaves(&compressed_block_leaves);

    {
        let mut checkpointed_block_tree = checkpointed_block_tree.write().await;
        checkpointed_block_tree
            .update_from_checkpoint(&prior_mmr_root, &block_leaves)
            .await
            .map_err(|e| eyre::eyre!("append_or_reorg_based_on_parent failed: {:?}", e))?;
    }
    let root = checkpointed_block_tree
        .read()
        .await
        .get_root()
        .await
        .map_err(|e| eyre::eyre!("get_root failed: {:?}", e))?;
    if root != new_mmr_root {
        return Err(eyre::eyre!(
            "Root mismatch: computed {:?} but expected {:?}",
            root,
            new_mmr_root
        ));
    }

    Ok(())
}
