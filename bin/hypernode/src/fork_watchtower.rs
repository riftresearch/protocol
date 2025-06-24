use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::DynProvider;
use alloy::sol_types::SolError;
use backoff::backoff::Backoff;
use backoff::exponential::ExponentialBackoff;
use bitcoin_data_engine::BitcoinDataEngine;
use bitcoin_light_client_core::{hasher::Keccak256Hasher, leaves::BlockLeaf, ChainTransition};
use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use bitcoincore_rpc_async::RpcApi;
use rift_indexer::engine::RiftIndexer;
use rift_core::giga::{RiftProgramInput, RustProofType};
use rift_sdk::bitcoin_utils::AsyncBitcoinClient;
use rift_sdk::proof_generator::{Proof, RiftProofGenerator};
use sol_bindings::{
    BlockProofParams, ChainworkTooLow, CheckpointNotEstablished, RiftExchangeHarnessInstance,
};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex, RwLockReadGuard};
use tokio::task::JoinSet;
use tokio::time;
use tracing::{error, info, info_span, warn, Instrument};

use crate::swap_watchtower::build_chain_transition_for_light_client_update;
use rift_sdk::txn_broadcast::{
    PreflightCheck, RevertInfo, TransactionBroadcaster, TransactionExecutionResult,
};

const TRANSACTION_BROADCAST_RETRY_MAX: usize = 5;

#[derive(Debug, Error)]
pub enum ForkWatchtowerError {
    #[error("Failed to update light client: {0}")]
    LightClientUpdateError(String),

    #[error("Failed to detect fork: {0}")]
    ForkDetectionError(String),

    #[error("Failed to generate proof: {0}")]
    ProofGenerationError(String),

    #[error("Timeout while generating proof")]
    ProofGenerationTimeout,

    #[error("Failed to broadcast transaction: {0}")]
    TransactionBroadcastError(String),

    #[error("Failed to build chain transition: {0}")]
    ChainTransitionBuildError(String),

    #[error("Transaction reverted: {0}")]
    TransactionReverted(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<eyre::Report> for ForkWatchtowerError {
    fn from(err: eyre::Report) -> Self {
        ForkWatchtowerError::Unknown(err.to_string())
    }
}

impl From<bitcoin::hashes::FromSliceError> for ForkWatchtowerError {
    fn from(err: bitcoin::hashes::FromSliceError) -> Self {
        ForkWatchtowerError::ForkDetectionError(format!("Failed to create block hash: {}", err))
    }
}

#[derive(Debug)]
pub enum ForkDetectionResult {
    NoFork,
    StaleChain,
    ForkDetected(ChainTransition),
}

#[derive(Debug)]
enum ForkWatchtowerEvent {
    NewTip(BlockLeaf),
    CheckForFork,
    MmrRootUpdated([u8; 32]),
}

pub struct ForkWatchtower;

impl ForkWatchtower {
    pub async fn run(
        contract_data_engine: Arc<RiftIndexer>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        evm_rpc: DynProvider,
        rift_exchange_address: Address,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        bitcoin_concurrency_limit: usize,
        proof_generator: Arc<RiftProofGenerator>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> eyre::Result<Self> {
        info!("Starting fork watchtower");

        let (event_sender, mut event_receiver) = mpsc::channel::<ForkWatchtowerEvent>(10);

        let rift_exchange =
            RiftExchangeHarnessInstance::new(rift_exchange_address, evm_rpc.clone());

        let fork_in_progress = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mut block_subscription = bitcoin_data_engine.subscribe_to_new_blocks();
        let event_sender_block = event_sender.clone();

        join_set.spawn(
            async move {
                loop {
                    match block_subscription.recv().await {
                        Ok(block) => {
                            if event_sender_block
                                .send(ForkWatchtowerEvent::NewTip(block))
                                .await
                                .is_err()
                            {
                                error!("Failed to forward event channel closed");
                                break;
                            }

                            if event_sender_block
                                .send(ForkWatchtowerEvent::CheckForFork)
                                .await
                                .is_err()
                            {
                                error!("Failed to send check for fork event channel closed");
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error receiving block: {}", e);
                            time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }

                Ok(())
            }
            .instrument(info_span!("Block Subscription Handler")),
        );

        let mut mmr_root_subscription = contract_data_engine.subscribe_to_mmr_root_updates();
        let event_sender_mmr = event_sender.clone();
        let mmr_root_subscription_cde = Arc::clone(&contract_data_engine);

        join_set.spawn(
            async move {
                loop {
                    match mmr_root_subscription.recv().await {
                        Ok(root) => {
                            if event_sender_mmr
                                .send(ForkWatchtowerEvent::MmrRootUpdated(root))
                                .await
                                .is_err()
                            {
                                error!("Failed to forward MMR root update event channel closed");
                                break;
                            }

                            if event_sender_mmr
                                .send(ForkWatchtowerEvent::CheckForFork)
                                .await
                                .is_err()
                            {
                                error!("Failed to send check for fork event channel closed");
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            error!("MMR root subscription lagged, missed {} messages", n);
                            mmr_root_subscription =
                                mmr_root_subscription_cde.subscribe_to_mmr_root_updates();
                        }
                        Err(e) => {
                            error!("Error receiving MMR root update: {}", e);
                            break;
                        }
                    }
                }

                Ok(())
            }
            .instrument(info_span!("MMR Root Subscription Handler")),
        );

        let fork_detection_lock = Arc::new(Mutex::new(()));

        {
            let contract_data_engine = Arc::clone(&contract_data_engine);
            let bitcoin_data_engine = Arc::clone(&bitcoin_data_engine);
            let btc_rpc = Arc::clone(&btc_rpc);
            let proof_generator = Arc::clone(&proof_generator);
            let transaction_broadcaster = Arc::clone(&transaction_broadcaster);
            let rift_exchange = rift_exchange.clone();
            let fork_in_progress = Arc::clone(&fork_in_progress);
            let fork_detection_lock = Arc::clone(&fork_detection_lock);

            join_set.spawn(
                async move {
                    while let Some(event) = event_receiver.recv().await {
                        match event {
                            ForkWatchtowerEvent::NewTip(_) | ForkWatchtowerEvent::CheckForFork => {
                                if !fork_in_progress.load(std::sync::atomic::Ordering::SeqCst) {
                                    let _lock = fork_detection_lock.lock().await;

                                    match Self::detect_fork(
                                        &contract_data_engine,
                                        &bitcoin_data_engine,
                                        &btc_rpc,
                                        bitcoin_concurrency_limit,
                                    )
                                    .await
                                    {
                                        Ok(ForkDetectionResult::ForkDetected(chain_transition)) => {
                                            info!("Fork detected, generating proof and resolving");

                                            fork_in_progress.store(true, std::sync::atomic::Ordering::SeqCst);

                                            let proof_generator_clone = proof_generator.clone();
                                            let rift_exchange_clone = rift_exchange.clone();
                                            let transaction_broadcaster_clone = transaction_broadcaster.clone();
                                            let fork_in_progress_clone = fork_in_progress.clone();

                                            tokio::spawn(
                                                async move {
                                                    Self::process_fork_resolution(
                                                        chain_transition,
                                                        &proof_generator_clone,
                                                        &rift_exchange_clone,
                                                        &transaction_broadcaster_clone,
                                                    )
                                                    .await;

                                                    fork_in_progress_clone
                                                        .store(false, std::sync::atomic::Ordering::SeqCst);
                                                }
                                                .instrument(info_span!("Fork Resolution Handler")),
                                            );
                                        }
                                        Ok(ForkDetectionResult::NoFork) => {
                                            info!("No fork detected at tip");
                                        }
                                        Ok(ForkDetectionResult::StaleChain) => {
                                            info!(
                                                "Light client chain is stale but valid, its included in BDE chain"
                                            );
                                        }
                                        Err(e) => {
                                            error!("Error detecting fork: {}", e);
                                        }
                                    }
                                }
                            }

                            ForkWatchtowerEvent::MmrRootUpdated(root) => {
                                info!("Received MMR root update event: {}", hex::encode(root));
                            }
                        }
                    }

                    Ok(())
                }
                .instrument(info_span!("Fork Watchtower")),
            );
        }

        Ok(Self)
    }

    pub async fn process_fork_resolution(
        chain_transition: ChainTransition,
        proof_generator: &Arc<RiftProofGenerator>,
        rift_exchange: &RiftExchangeHarnessInstance<DynProvider>,
        transaction_broadcaster: &Arc<TransactionBroadcaster>,
    ) {
        let proof_result = Self::generate_light_client_update_proof(
            chain_transition.clone(),
            Arc::clone(proof_generator),
        )
        .await;

        let proof = match proof_result {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to generate proof: {}", e);
                return;
            }
        };

        info!("Generated proof for fork resolution");

        let (public_values, auxiliary_data) = {
            let rift_program_input = match RiftProgramInput::builder()
                .proof_type(RustProofType::LightClientOnly)
                .light_client_input(chain_transition)
                .build()
            {
                Ok(input) => input,
                Err(e) => {
                    error!("Failed to build program input: {}", e);
                    return;
                }
            };

            rift_program_input.get_auxiliary_light_client_data()
        };

        let block_proof_params = BlockProofParams {
            priorMmrRoot: public_values.priorMmrRoot,
            newMmrRoot: public_values.newMmrRoot,
            tipBlockLeaf: public_values.tipBlockLeaf,
            compressedBlockLeaves: auxiliary_data.compressed_leaves.into(),
        };

        let proof_bytes = match &proof.proof {
            Some(p) => p.bytes(),
            None => {
                warn!("Using mock proof for light client update");
                Vec::new()
            }
        };

        let call = rift_exchange.updateLightClient(block_proof_params.clone(), proof_bytes.into());
        let calldata = call.calldata().to_owned();
        let transaction_request = call.into_transaction_request();

        info!("Broadcasting fork resolution transaction");

        let mut backoff: backoff::exponential::ExponentialBackoff<backoff::SystemClock> =
            ExponentialBackoff {
                initial_interval: Duration::from_millis(500),
                max_interval: Duration::from_secs(10),
                multiplier: 1.5,
                max_elapsed_time: Some(Duration::from_secs(120)),
                ..Default::default()
            };

        let mut retries = 0;
        let max_retries = TRANSACTION_BROADCAST_RETRY_MAX;

        loop {
            retries += 1;
            info!(
                "Attempt {} of {} to broadcast fork resolution",
                retries, max_retries
            );

            match transaction_broadcaster
                .broadcast_transaction(
                    calldata.clone(),
                    transaction_request.clone(),
                    PreflightCheck::Simulate,
                )
                .await
            {
                Ok(TransactionExecutionResult::Success(receipt)) => {
                    info!(
                        "Fork resolution transaction successful: {:?}",
                        receipt.transaction_hash
                    );
                    return;
                }
                Ok(TransactionExecutionResult::Revert(revert_info)) => {
                    let should_retry = Self::handle_transaction_revert(&revert_info);

                    if !should_retry || retries >= max_retries {
                        error!(
                            "Transaction reverted with unrecoverable error: {:?}",
                            revert_info
                        );
                        return;
                    }

                    warn!(
                        "Transaction reverted with recoverable error, retry ({}/{})",
                        retries, max_retries
                    );
                }
                Ok(TransactionExecutionResult::InvalidRequest(msg)) => {
                    error!("Invalid transaction request: {}", msg);
                    return;
                }
                Ok(TransactionExecutionResult::UnknownError(msg)) => {
                    if retries >= max_retries {
                        error!("Max retries reached for transaction broadcast: {}", msg);
                        return;
                    }
                    warn!(
                        "Transaction failed with unknown error, retry ({}/{}): {}",
                        retries, max_retries, msg
                    );
                }
                Err(e) => {
                    if retries >= max_retries {
                        error!("Max retries reached for transaction broadcast: {}", e);
                        return;
                    }
                    error!("Failed to send transaction, will retry: {}", e);
                }
            }

            if let Some(wait_time) = backoff.next_backoff() {
                info!("Waiting {:?} before next attempt", wait_time);
                tokio::time::sleep(wait_time).await;
            } else {
                error!("Maximum backoff time exceeded");
                return;
            }
        }
    }

    pub async fn detect_fork(
        contract_data_engine: &Arc<RiftIndexer>,
        bitcoin_data_engine: &Arc<BitcoinDataEngine>,
        btc_rpc: &Arc<AsyncBitcoinClient>,
        bitcoin_concurrency_limit: usize,
    ) -> Result<ForkDetectionResult, ForkWatchtowerError> {
        info!("Checking for fork at chain tips only");

        let light_client_mmr = contract_data_engine.checkpointed_block_tree.read().await;
        let bitcoin_mmr = bitcoin_data_engine.indexed_mmr.read().await;

        let light_client_tip_index = light_client_mmr.get_leaf_count().await.map_err(|e| {
            ForkWatchtowerError::ForkDetectionError(format!(
                "Failed to get light client leaf count: {}",
                e
            ))
        })? - 1;

        let light_client_tip_leaf = light_client_mmr
            .get_leaf_by_leaf_index(light_client_tip_index)
            .await
            .map_err(|e| {
                ForkWatchtowerError::ForkDetectionError(format!(
                    "Failed to get light client tip leaf: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                ForkWatchtowerError::ForkDetectionError(
                    "Light client tip leaf not found".to_string(),
                )
            })?;

        let bitcoin_tip_index = bitcoin_mmr.get_leaf_count().await.map_err(|e| {
            ForkWatchtowerError::ForkDetectionError(format!(
                "Failed to get bitcoin leaf count: {}",
                e
            ))
        })? - 1;

        let bitcoin_tip_leaf = bitcoin_mmr
            .get_leaf_by_leaf_index(bitcoin_tip_index)
            .await
            .map_err(|e| {
                ForkWatchtowerError::ForkDetectionError(format!(
                    "Failed to get bitcoin tip leaf: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                ForkWatchtowerError::ForkDetectionError("Bitcoin tip leaf not found".to_string())
            })?;

        if light_client_tip_leaf.block_hash == bitcoin_tip_leaf.block_hash {
            info!(
                message = "No fork tips match exactly",
                tip_hash = hex::encode(light_client_tip_leaf.block_hash),
            );
            return Ok(ForkDetectionResult::NoFork);
        }

        let light_client_chainwork = light_client_tip_leaf.chainwork_as_u256();
        let bitcoin_chainwork = bitcoin_tip_leaf.chainwork_as_u256();

        if light_client_chainwork == bitcoin_chainwork {
            info!(
                message = "Tips have equal so first seen policy (no fork)",
                chainwork = format!("{:x}", light_client_chainwork),
            );
            return Ok(ForkDetectionResult::NoFork);
        }

        let is_included =
            Self::check_leaf_inclusion_in_bde(&light_client_tip_leaf, &bitcoin_mmr, btc_rpc)
                .await?;

        if is_included {
            info!(
                message = "Light client tip is included in BDE chain, no fork",
                light_client_tip = hex::encode(light_client_tip_leaf.block_hash),
            );
            return Ok(ForkDetectionResult::StaleChain);
        }

        if light_client_chainwork > bitcoin_chainwork {
            info!(
                message =
                    "Fork detected light client has block not in BDE chain with higher chainwork",
                light_client_tip = hex::encode(light_client_tip_leaf.block_hash),
                light_client_chainwork = format!("{:x}", light_client_chainwork),
                bitcoin_chainwork = format!("{:x}", bitcoin_chainwork),
            );
        } else {
            info!(
                message =
                    "Fork detected light client tip not in BDE chain and BDE has more chainwork",
                light_client_tip = hex::encode(light_client_tip_leaf.block_hash),
                light_client_chainwork = format!("{:x}", light_client_chainwork),
                bitcoin_chainwork = format!("{:x}", bitcoin_chainwork),
            );
        }

        let chain_transition = build_chain_transition_for_light_client_update(
            Arc::clone(btc_rpc),
            &bitcoin_mmr,
            &light_client_mmr,
            bitcoin_concurrency_limit,
        )
        .await
        .map_err(|e| ForkWatchtowerError::ChainTransitionBuildError(e.to_string()))?;

        Ok(ForkDetectionResult::ForkDetected(chain_transition))
    }

    pub async fn check_leaf_inclusion_in_bde(
        leaf: &BlockLeaf,
        bitcoin_mmr: &RwLockReadGuard<'_, rift_sdk::indexed_mmr::IndexedMMR<Keccak256Hasher>>,
        btc_rpc: &Arc<AsyncBitcoinClient>,
    ) -> Result<bool, ForkWatchtowerError> {
        let leaf_hash = leaf.hash::<Keccak256Hasher>();
        let leaf_result = bitcoin_mmr
            .get_leaf_by_leaf_hash(&leaf_hash)
            .await
            .map_err(|e| {
                ForkWatchtowerError::ForkDetectionError(format!(
                    "Failed to query leaf in BDE: {}",
                    e
                ))
            })?;

        if leaf_result.is_some() {
            info!(
                "Leaf found directly in BDE MMR: height={}, hash={}",
                leaf.height,
                hex::encode(leaf.block_hash)
            );
            return Ok(true);
        }

        let natural_block_hash = leaf.natural_block_hash();

        info!(
            "Checking if block exists in Bitcoin chain: height={}, hash={}",
            leaf.height,
            hex::encode(natural_block_hash)
        );

        let block_header_result = btc_rpc
            .get_block_header_verbose(&bitcoincore_rpc_async::bitcoin::BlockHash::from_slice(
                &natural_block_hash,
            )?)
            .await;

        match block_header_result {
            Ok(header_info) => {
                let block_height = header_info.height as u32;

                let mut is_in_main_chain =
                    header_info.confirmations > 0 && block_height == leaf.height;

                info!(
                    "Block found in Bitcoin chain: confirmations={}, chain height={}, block height={}, expected height={}",
                    header_info.confirmations, block_height, block_height, leaf.height
                );

                if is_in_main_chain {
                    if let Ok(height_hash) = btc_rpc.get_block_hash(block_height as u64).await {
                        let height_hash_str = height_hash.to_string();
                        let block_hash_str = bitcoincore_rpc_async::bitcoin::BlockHash::from_slice(
                            &natural_block_hash,
                        )?
                        .to_string();

                        if height_hash_str != block_hash_str {
                            info!(
                                "Found different block at height {} in main chain Fork detected Main chain hash: {}, Block hash: {}",
                                block_height, height_hash_str, block_hash_str
                            );
                            is_in_main_chain = false;
                        }
                    }
                }

                info!(
                    "Block check result: is_in_main_chain={}, confirmations={}, height={}, expected_height={}",
                    is_in_main_chain, header_info.confirmations, block_height, leaf.height
                );

                Ok(is_in_main_chain)
            }
            Err(bitcoincore_rpc_async::Error::JsonRpc(
                bitcoincore_rpc_async::jsonrpc::error::Error::Rpc(ref rpcerr),
            )) if rpcerr.code == -5 => {
                info!(
                    "Block not found in Bitcoin chain at all: height={}, hash={}",
                    leaf.height,
                    hex::encode(natural_block_hash)
                );
                Ok(false)
            }
            Err(e) => {
                error!("Error checking block in Bitcoin chain: {}", e);
                Err(ForkWatchtowerError::ForkDetectionError(format!(
                    "Failed to query block header: {}",
                    e
                )))
            }
        }
    }

    async fn generate_light_client_update_proof(
        chain_transition: ChainTransition,
        proof_generator: Arc<RiftProofGenerator>,
    ) -> Result<Proof, ForkWatchtowerError> {
        info!(message = "Generating light client update proof");

        let program_input = RiftProgramInput::builder()
            .proof_type(RustProofType::LightClientOnly)
            .light_client_input(chain_transition)
            .build()
            .map_err(|e| ForkWatchtowerError::ProofGenerationError(e.to_string()))?;

        let mut backoff: backoff::exponential::ExponentialBackoff<backoff::SystemClock> =
            ExponentialBackoff::default();
        backoff.max_elapsed_time = Some(Duration::from_secs(300));

        let proof_result = loop {
            match proof_generator.prove(&program_input).await {
                Ok(proof) => break Ok(proof),
                Err(e) => {
                    warn!("Proof generation failed, retrying: {}", e);

                    if let Some(duration) = backoff.next_backoff() {
                        time::sleep(duration).await;
                    } else {
                        break Err(ForkWatchtowerError::ProofGenerationError(e.to_string()));
                    }
                }
            }
        };

        proof_result
    }

    pub fn handle_transaction_revert(revert_info: &RevertInfo) -> bool {
        info!(
            "Analyzing transaction revert: {:?}, debug command: {}",
            revert_info.error_payload, revert_info.debug_cli_command
        );

        if let Some(data_raw) = &revert_info.error_payload.data {
            let data_str = data_raw.to_string();
            info!("data_str: {:?}", data_str);
            // Remove quotes and 0x prefix, format -> "0x..."
            let hex_str = &data_str[3..data_str.len() - 1];
            info!("hex_str: {:?}", hex_str);
            if let Ok(data) = hex::decode(hex_str) {
                // Matching with Error Selector
                // /// The error selector: `keccak256(SIGNATURE)[0..4]`
                // const SELECTOR: [u8; 4];
                if data.len() >= 4 {
                    let selector = &data[0..4];
                    info!("selector: {:?}", selector);
                    info!(
                        "code for Checkpoint not established: {:?}",
                        CheckpointNotEstablished::SELECTOR
                    );
                    info!(
                        "code for Chainwork too low: {:?}",
                        ChainworkTooLow::SELECTOR
                    );

                    if selector == CheckpointNotEstablished::SELECTOR {
                        info!("Checkpoint not established");
                        // Dont retry if check not established
                        return false;
                    }

                    if selector == ChainworkTooLow::SELECTOR {
                        info!("Chainwork too low");
                        // Dont retry if chainwork is too low
                        // The fork watchtower will automatically try again when it detects the next update
                        return false;
                    }
                }
            }
        }

        info!("Unknown revert reason, will not attempt retry");
        false
    }
}
