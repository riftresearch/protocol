use alloy::{
    primitives::{Address, FixedBytes},
    providers::{ext::TraceApi, DynProvider, Provider},
    rpc::types::{trace::parity::Action, BlockNumberOrTag, Filter, Log},
    sol_types::{SolCall, SolEvent},
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
    submitPaymentProofs_1Call, updateLightClientCall, AuctionUpdated, BitcoinLightClientUpdated,
    Order, OrdersUpdated, PaymentsUpdated,
};

use std::{path::PathBuf, sync::Arc};
use tokio::{
    sync::{broadcast, RwLock},
    task::JoinSet,
};
use tracing::{info, info_span, warn, Instrument};

use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    db::{
        add_order, add_payment, get_orders_for_recipient, get_otc_swap_by_order_hash,
        get_payments_ready_to_be_settled, get_virtual_swaps, setup_swaps_database,
        update_order_to_refunded, update_payment_to_settled, ChainAwarePaymentWithOrder,
    },
    models::ChainAwareOrder,
};
use crate::{
    db::{get_oldest_active_order, get_order_by_hash},
    models::OTCSwap,
};

#[derive(Debug, Clone)]
pub struct ContractDataEngine {
    pub checkpointed_block_tree: Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
    pub swap_database_connection: Arc<tokio_rusqlite::Connection>,
    server_started: Arc<AtomicBool>,
    initial_sync_complete: Arc<AtomicBool>,
    initial_sync_broadcaster: broadcast::Sender<bool>,
    mmr_root_broadcaster: broadcast::Sender<[u8; 32]>,
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

        // Initialize the MMR root broadcaster
        let (mmr_root_broadcaster, _) = broadcast::channel::<[u8; 32]>(16);

        Ok(Self {
            checkpointed_block_tree,
            swap_database_connection,
            initial_sync_complete: Arc::new(AtomicBool::new(false)),
            initial_sync_broadcaster: broadcast::channel(1).0,
            server_started: Arc::new(AtomicBool::new(false)),
            mmr_root_broadcaster,
        })
    }

    pub async fn wait_for_initial_sync(&self) -> eyre::Result<()> {
        let mut rx = self.initial_sync_broadcaster.subscribe();
        if self.initial_sync_complete.load(Ordering::SeqCst) {
            return Ok(());
        }
        rx.recv().await.map(|_| ()).map_err(Into::into)
    }

    /// Seeds the DataEngine and immediately starts the event listener.
    /// Internally this uses seed() and then start_server().
    pub async fn start(
        database_location: &DatabaseLocation,
        provider: DynProvider,
        rift_exchange_address: Address,
        deploy_block_number: u64,
        log_chunk_size: u64,
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
                log_chunk_size,
                join_set,
            )
            .await?;

        Ok(engine)
    }

    /// Starts the event listener server by passing the remaining configuration.
    /// This method will only spawn the event listener once.
    pub async fn start_event_listener(
        &mut self,
        provider: DynProvider,
        rift_exchange_address: Address,
        deploy_block_number: u64,
        chunk_size: u64,
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
        let initial_sync_broadcaster_clone = self.initial_sync_broadcaster.clone();

        let self_clone = Arc::new(self.clone());
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
                    initial_sync_broadcaster_clone,
                    chunk_size,
                    &self_clone,
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

    pub async fn get_orders_for_recipient(
        &self,
        address: Address,
        deposit_block_cutoff: u64,
    ) -> Result<Vec<Order>> {
        get_orders_for_recipient(
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

    pub async fn get_oldest_active_order(
        &self,
        current_block_timestamp: u64,
    ) -> Result<Option<ChainAwareOrder>> {
        get_oldest_active_order(&self.swap_database_connection, current_block_timestamp).await
    }

    pub async fn get_otc_swap_by_order_hash(
        &self,
        deposit_id: [u8; 32],
    ) -> Result<Option<OTCSwap>> {
        get_otc_swap_by_order_hash(&self.swap_database_connection, deposit_id).await
    }

    pub async fn get_payments_ready_to_be_settled(
        &self,
        current_block_timestamp: u64,
    ) -> Result<Vec<ChainAwarePaymentWithOrder>> {
        get_payments_ready_to_be_settled(&self.swap_database_connection, current_block_timestamp)
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

    // Subscribe to MMR root updates
    pub fn subscribe_to_mmr_root_updates(&self) -> broadcast::Receiver<[u8; 32]> {
        self.mmr_root_broadcaster.subscribe()
    }

    // Get the current MMR root but w/ cached value
    pub async fn get_mmr_root(&self) -> Result<[u8; 32]> {
        let checkpointed_block_tree = self.checkpointed_block_tree.read().await;
        checkpointed_block_tree
            .get_root()
            .await
            .map_err(|e| eyre::eyre!(e))
    }

    // update MMR root and broadcast changes
    pub async fn update_mmr_root(&self, new_root: [u8; 32]) -> Result<()> {
        let _ = self.mmr_root_broadcaster.send(new_root);
        Ok(())
    }

    pub async fn get_mmr_bagged_peak(&self) -> Result<Digest> {
        let checkpointed_block_tree = self.checkpointed_block_tree.read().await;
        checkpointed_block_tree
            .get_bagged_peak()
            .await
            .map_err(|e| eyre::eyre!(e))
    }

    pub async fn get_order_by_hash(&self, deposit_id: [u8; 32]) -> Result<Option<ChainAwareOrder>> {
        get_order_by_hash(&self.swap_database_connection, deposit_id).await
    }

    pub async fn reset_mmr_for_testing(&self, bde_leaves: &[BlockLeaf]) -> Result<()> {
        let temp_db_location = DatabaseLocation::InMemory;
        let mut temp_tree = CheckpointedBlockTree::open(&temp_db_location).await?;
        let root = temp_tree.create_seed_checkpoint(bde_leaves).await?;

        *self.checkpointed_block_tree.write().await = temp_tree;
        self.update_mmr_root(root).await?;

        Ok(())
    }
}

fn get_qualified_swaps_database_path(database_location: String) -> String {
    let path = PathBuf::from(database_location);
    let swaps_db_path = path.join("swaps.db");
    swaps_db_path.to_str().expect("Invalid path").to_string()
}

/// Process every past + future event for `rift_exchange_address` without gaps.
///
/// 1.  Start the Web-socket subscription *first* (race-free).
/// 2.  Push every live log into an **unbounded** MPSC channel; it will grow
///     in RAM for as long as the synchronous back-fill lasts.
/// 3.  Snapshot the chain head once, then walk `[deploy_block … head]`
///     in `CHUNK_SIZE` windows.
/// 4.  Drain whatever accumulated in the channel while back-filling.
/// 5.  Mark initial sync done, then forever `recv` from the channel.
///
/// Safety notes:
/// * No log loss, no double processing (checkpoint tree dedupes reorgs).
/// * Memory is the only buffer; high-traffic contracts + slow back-fills
///   can eat GBs of RAM.  Instrument `BACKLOG.store(len)` if you want alerts.
pub async fn listen_for_events(
    provider: DynProvider,
    db_conn: &Arc<tokio_rusqlite::Connection>,
    checkpointed_block_tree: Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
    rift_exchange_address: Address,
    deploy_block_number: u64,
    initial_sync_complete: Arc<AtomicBool>,
    initial_sync_broadcaster: broadcast::Sender<bool>,
    chunk_size: u64,
    contract_data_engine: &Arc<ContractDataEngine>,
) -> Result<()> {
    use std::sync::atomic::Ordering;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

    // ---------------------------------------------------------------------
    // 1. Live subscription first (race-free)
    // ---------------------------------------------------------------------
    let sub = provider
        .subscribe_logs(&Filter::new().address(rift_exchange_address))
        .await?;
    let mut live_stream = sub.into_stream();

    // 2. Unbounded buffer for live logs
    let (tx, mut rx): (_, UnboundedReceiver<Log>) = unbounded_channel();
    tokio::spawn(async move {
        while let Some(log) = live_stream.next().await {
            if tx.send(log).is_err() {
                break;
            }
        }
    });

    // ---------------------------------------------------------------------
    // 3. Historical back-fill
    // ---------------------------------------------------------------------
    let head = provider.get_block_number().await?; // single snapshot
    let mut from = deploy_block_number;

    while from <= head {
        let to = head.min(from + chunk_size - 1);
        let logs = provider
            .get_logs(
                &Filter::new()
                    .address(rift_exchange_address)
                    .from_block(BlockNumberOrTag::Number(from))
                    .to_block(BlockNumberOrTag::Number(to)),
            )
            .await?;

        // Synchronous / ordered processing
        for log in logs {
            process_log(
                &log,
                db_conn,
                &checkpointed_block_tree,
                provider.clone(),
                rift_exchange_address,
                contract_data_engine,
            )
            .await?;
        }
        from = to + 1;
    }

    // ---------------------------------------------------------------------
    // 4. Drain buffered live events emitted during back-fill
    // ---------------------------------------------------------------------
    while let Ok(log) = rx.try_recv() {
        process_log(
            &log,
            db_conn,
            &checkpointed_block_tree,
            provider.clone(),
            rift_exchange_address,
            contract_data_engine,
        )
        .await?;
    }

    // ---------------------------------------------------------------------
    // 5. Signal initial sync complete
    // ---------------------------------------------------------------------
    initial_sync_complete.store(true, Ordering::SeqCst);
    {
        let _ = initial_sync_broadcaster.send(true);
    }

    // ---------------------------------------------------------------------
    // 6. Tail the unbounded channel forever
    // ---------------------------------------------------------------------
    while let Some(log) = rx.recv().await {
        process_log(
            &log,
            db_conn,
            &checkpointed_block_tree,
            provider.clone(),
            rift_exchange_address,
            contract_data_engine,
        )
        .await?;
    }

    // If the subscription closes we exit the function gracefully
    Ok(())
}

async fn process_log(
    log: &Log,
    db_conn: &Arc<tokio_rusqlite::Connection>,
    checkpointed_block_tree: &Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
    provider: DynProvider,
    rift_exchange_address: Address,
    contract_data_engine: &Arc<ContractDataEngine>,
) -> Result<()> {
    info!("Processing log: {:?}", log);

    // If there's no topic then that's a critical error.
    let topic = log
        .topic0()
        .ok_or_else(|| eyre::eyre!("No topic found in log"))?;

    match *topic {
        OrdersUpdated::SIGNATURE_HASH => {
            info_span!("handle_order_updated")
                .in_scope(|| handle_order_updated_event(log, db_conn))
                .await?;
        }
        PaymentsUpdated::SIGNATURE_HASH => {
            info_span!("handle_payment_updated")
                .in_scope(|| handle_payment_updated_event(log, db_conn))
                .await?;
        }
        BitcoinLightClientUpdated::SIGNATURE_HASH => {
            info_span!("handle_bitcoin_light_client_updated")
                .in_scope(|| {
                    handle_bitcoin_light_client_updated_event(
                        log,
                        provider.clone(),
                        checkpointed_block_tree.clone(),
                        rift_exchange_address,
                        contract_data_engine,
                    )
                })
                .await?;
        }
        _ => {
            warn!("Unknown event topic");
        }
    }

    Ok(())
}

async fn handle_order_updated_event(
    log: &Log,
    db_conn: &Arc<tokio_rusqlite::Connection>,
) -> Result<()> {
    info!("Received OrderUpdated event...");

    // Propagate any decoding error.
    let decoded = OrdersUpdated::decode_log(&log.inner)
        .map_err(|e| eyre::eyre!("Failed to decode OrderUpdated event: {:?}", e))?;

    let orders = decoded.data.orders;
    let log_txid = log
        .transaction_hash
        .ok_or_else(|| eyre::eyre!("Missing txid in OrderUpdated event"))?;
    let log_block_number = log
        .block_number
        .ok_or_else(|| eyre::eyre!("Missing block number in OrderUpdated event"))?;
    let log_block_hash = log
        .block_hash
        .ok_or_else(|| eyre::eyre!("Missing block hash in OrderUpdated event"))?;

    for order in orders {
        match decoded.data.context {
            0 /* OrderUpdateContext::Created */ => {
                add_order(
                    db_conn,
                    order,
                    log_block_number,
                    log_block_hash.into(),
                    log_txid.into(),
                )
                .await
                .map_err(|e| eyre::eyre!("add_order failed: {:?}", e))?;
            }
            1 /* OrderUpdateContext::Refunded */ => {
                update_order_to_refunded(
                    db_conn,
                    order.salt.into(),
                    log_txid.into(),
                    log_block_number,
                    log_block_hash.into(),
                )
                .await
                .map_err(|e| eyre::eyre!("update_order_to_refunded failed: {:?}", e))?;
            }
            _ => {}
        }
    }

    Ok(())
}

async fn handle_payment_updated_event(
    log: &Log,
    db_conn: &Arc<tokio_rusqlite::Connection>,
) -> Result<()> {
    info!("Received PaymentUpdated event");

    // Propagate any decoding error.
    let decoded = PaymentsUpdated::decode_log(&log.inner)
        .map_err(|e| eyre::eyre!("Failed to decode PaymentUpdated event: {:?}", e))?;

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
            for payment in decoded.data.payments {
                info!(
                    "Received PaymentUpdated event: payment_index = {:?}",
                    payment.index.to::<u64>()
                );
                add_payment(
                    db_conn,
                    &payment,
                    log_block_number,
                    log_block_hash.into(),
                    log_txid.into(),
                )
                .await
                .map_err(|e| eyre::eyre!("add_payment failed: {:?}", e))?;
            }
        }
        1 /* SwapUpdateContext::Complete */ => {
            for payment in decoded.data.payments {
                update_payment_to_settled(
                    db_conn,
                    payment.index.to::<u64>(),
                    log_txid.into(),
                    log_block_number,
                    log_block_hash.into(),
                )
                .await
                .map_err(|e| eyre::eyre!("update_payment_to_settled failed: {:?}", e))?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_bitcoin_light_client_updated_event(
    log: &Log,
    provider: DynProvider,
    checkpointed_block_tree: Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
    rift_exchange_address: Address,
    contract_data_engine: &Arc<ContractDataEngine>,
) -> Result<()> {
    info!("Received BitcoinLightClientUpdated event");
    let txid = log
        .transaction_hash
        .ok_or_else(|| eyre::eyre!("Missing txid in BitcoinLightClientUpdated event"))?;

    // Propagate any decoding error.
    let decoded = BitcoinLightClientUpdated::decode_log(&log.inner)
        .map_err(|e| eyre::eyre!("Failed to decode BitcoinLightClientUpdated event: {:?}", e))?;

    let block_tree_data = &decoded.data;
    let prior_mmr_root = block_tree_data.priorMmrRoot.0;
    let new_mmr_root = block_tree_data.newMmrRoot.0;
    // TODO: We need to get the compressed block leaves from the calldata using trace_transaction
    let compressed_block_leaves = extract_compressed_block_leaves_from_light_client_updating_tx(
        provider,
        rift_exchange_address,
        &prior_mmr_root,
        &new_mmr_root,
        txid,
    )
    .await?;
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

    contract_data_engine.update_mmr_root(new_mmr_root).await?;

    Ok(())
}

/// Extracts the calldata from a light client updating transaction.
/// Done by tracing the transaction and finding the calldata which has
/// has a 4 byte selector for any function that fires the LightClientUpdated event.
/// These functions are:
/// - updateLightClient
/// - submitPaymentProofs()

async fn extract_compressed_block_leaves_from_light_client_updating_tx(
    provider: DynProvider,
    rift_exchange_address: Address,
    expected_prior_mmr_root: &[u8; 32],
    expected_new_mmr_root: &[u8; 32],
    txid: FixedBytes<32>,
) -> Result<Vec<u8>> {
    /*
        let call_tracer_options = GethDebugTracingOptions {
            config: GethDefaultTracingOptions::default(),
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            ..Default::default()
        };
    */

    let transaction_trace = provider.trace_transaction(txid).await?;

    let compressed_block_leaves = transaction_trace
        .iter()
        // Grab all CALL
        .filter_map(|call| match &call.trace.action {
            Action::Call(call) => Some(call),
            _ => None,
        })
        // Only calls to the rift exchange address
        .filter_map(|call| {
            if call.to == rift_exchange_address {
                Some(call.input.clone())
            } else {
                None
            }
        })
        // Only calldata that starts with the submitPaymentProofs_1 selector OR the updateLightClient selector
        .filter_map(|calldata| {
            if calldata.len() < 4 {
                return None;
            }
            let selector: &[u8; 4] = &calldata[0..4].try_into().unwrap();
            match *selector {
                submitPaymentProofs_1Call::SELECTOR => {
                    submitPaymentProofs_1Call::abi_decode(&calldata)
                        .map(|decoded| decoded.blockProofParams)
                        .ok()
                }
                updateLightClientCall::SELECTOR => updateLightClientCall::abi_decode(&calldata)
                    .map(|decoded| decoded.blockProofParams)
                    .ok(),
                _ => None,
            }
        })
        // Filter out any calldata not strictly related to this specific event
        .filter_map(|block_proof_params| {
            if block_proof_params.priorMmrRoot != expected_prior_mmr_root {
                return None;
            }
            if block_proof_params.newMmrRoot != expected_new_mmr_root {
                return None;
            }
            Some(block_proof_params.compressedBlockLeaves)
        })
        .collect::<Vec<_>>();
    let compressed_block_leaves = compressed_block_leaves.first().ok_or_else(|| {
        eyre::eyre!("No compressed block leaves found in light client updating tx")
    })?;
    Ok(compressed_block_leaves.to_vec())
}
