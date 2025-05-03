use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, FixedBytes};
use alloy::providers::DynProvider;
use backoff::backoff::Backoff;
use backoff::exponential::ExponentialBackoff;
use bitcoin_data_engine::BitcoinDataEngine;
use bitcoin_light_client_core::{hasher::Keccak256Hasher, leaves::BlockLeaf, ChainTransition};
use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use bitcoincore_rpc_async::RpcApi;
use data_engine::engine::ContractDataEngine;
use metrics::{counter, gauge, histogram};
use rift_core::giga::{RiftProgramInput, RustProofType};
use rift_sdk::bitcoin_utils::AsyncBitcoinClient;
use rift_sdk::proof_generator::{Proof, RiftProofGenerator};
use scopeguard::defer;
use sol_bindings::{BlockProofParams, RiftExchangeHarnessInstance};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, Mutex, RwLockReadGuard};
use tokio::task::JoinSet;
use tokio::time;
use tracing::{error, info, info_span, warn, Instrument};

use crate::swap_watchtower::build_chain_transition_for_light_client_update;
use crate::txn_broadcast::{
    PreflightCheck, RevertInfo, TransactionBroadcaster, TransactionExecutionResult,
    TransactionStatusUpdate,
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
    TransactionStatus(TransactionStatusUpdate),
    CheckForFork,
    MmrRootUpdated([u8; 32]),
}

#[derive(Debug)]
struct PendingForkResolution {
    chain_transition: ChainTransition,
    expected_mmr_root: [u8; 32],
    transaction_hash: Option<FixedBytes<32>>,
    retries: usize,
}

pub struct ForkWatchtower;

impl ForkWatchtower {
    pub fn run(
        contract_data_engine: Arc<ContractDataEngine>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        evm_rpc: DynProvider,
        rift_exchange_address: Address,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        bitcoin_concurrency_limit: usize,
        proof_generator: Arc<RiftProofGenerator>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) {
        join_set.spawn(
            async move {
                Self::event_driven_fork_watcher(
                    contract_data_engine,
                    bitcoin_data_engine,
                    btc_rpc,
                    evm_rpc,
                    rift_exchange_address,
                    transaction_broadcaster,
                    bitcoin_concurrency_limit,
                    proof_generator,
                )
                .await
            }
            .instrument(info_span!("Fork Watchtower")),
        );
    }

    async fn event_driven_fork_watcher(
        contract_data_engine: Arc<ContractDataEngine>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        evm_rpc: DynProvider,
        rift_exchange_address: Address,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        bitcoin_concurrency_limit: usize,
        proof_generator: Arc<RiftProofGenerator>,
    ) -> eyre::Result<()> {
        info!("Starting tip-based fork watchtower");

        counter!("fork_watchtower.started").increment(1);
        gauge!("fork_watchtower.running").set(1.0);

        defer! {
            gauge!("fork_watchtower.running").set(0.0);
        }

        let (event_sender, mut event_receiver) = mpsc::channel::<ForkWatchtowerEvent>(10);

        let rift_exchange =
            RiftExchangeHarnessInstance::new(rift_exchange_address, evm_rpc.clone());

        let mut pending_resolution: Option<PendingForkResolution> = None;

        let mut block_subscription = bitcoin_data_engine.subscribe_to_new_blocks();
        let event_sender_block = event_sender.clone();
        
        tokio::spawn(async move {
            loop {
                match block_subscription.recv().await {
                    Ok(block) => {
                        if event_sender_block
                            .send(ForkWatchtowerEvent::NewTip(block))
                            .await
                            .is_err()
                        {
                            error!("Failed to forward tip event, channel closed");
                            break;
                        }
                        
                        if event_sender_block
                            .send(ForkWatchtowerEvent::CheckForFork)
                            .await
                            .is_err()
                        {
                            error!("Failed to send check for fork event, channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error receiving block: {}", e);
                        time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });

        let mut tx_status_subscription = transaction_broadcaster.subscribe_to_status_updates();
        let event_sender_tx = event_sender.clone();

        let tx_broadcaster_clone = Arc::clone(&transaction_broadcaster);
        tokio::spawn(async move {
            loop {
                match tx_status_subscription.recv().await {
                    Ok(status) => {
                        if event_sender_tx
                            .send(ForkWatchtowerEvent::TransactionStatus(status))
                            .await
                            .is_err()
                        {
                            error!("Failed to forward transaction status event, channel closed");
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        error!(
                            "Transaction status subscription lagged, missed {} messages",
                            n
                        );
                        tx_status_subscription = tx_broadcaster_clone.subscribe_to_status_updates();
                    }
                    Err(e) => {
                        error!("Error receiving transaction status: {}", e);
                        break;
                    }
                }
            }
        });

        let mut mmr_root_subscription = contract_data_engine.subscribe_to_mmr_root_updates();
        let event_sender_mmr = event_sender.clone();

        let mmr_root_subscription_cde = Arc::clone(&contract_data_engine);
        tokio::spawn(async move {
            loop {
                match mmr_root_subscription.recv().await {
                    Ok(root) => {
                        if event_sender_mmr
                            .send(ForkWatchtowerEvent::MmrRootUpdated(root))
                            .await
                            .is_err()
                        {
                            error!("Failed to forward MMR root update event, channel closed");
                            break;
                        }
                        
                        if event_sender_mmr
                            .send(ForkWatchtowerEvent::CheckForFork)
                            .await
                            .is_err()
                        {
                            error!("Failed to send check for fork event, channel closed");
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
        });

        let fork_detection_lock = Arc::new(Mutex::new(()));

        while let Some(event) = event_receiver.recv().await {
            match event {
                ForkWatchtowerEvent::NewTip(_) | ForkWatchtowerEvent::CheckForFork => {
                    if pending_resolution.is_none() {
                        let _lock = fork_detection_lock.lock().await;

                        let start = time::Instant::now();
                        match Self::detect_fork(
                            &contract_data_engine,
                            &bitcoin_data_engine,
                            &btc_rpc,
                            bitcoin_concurrency_limit,
                        )
                        .await
                        {
                            Ok(ForkDetectionResult::ForkDetected(chain_transition)) => {
                                info!("Fork detected, generating proof");
                                counter!("fork_watchtower.fork_detected").increment(1);
                                histogram!("fork_watchtower.detection_time")
                                    .record(start.elapsed().as_secs_f64());

                                Self::handle_fork_resolution(
                                    chain_transition,
                                    &proof_generator,
                                    &rift_exchange,
                                    &transaction_broadcaster,
                                    &mut pending_resolution,
                                )
                                .await;
                            }
                            Ok(ForkDetectionResult::NoFork) => {
                                info!("No fork detected at tip");
                                counter!("fork_watchtower.no_fork_detected").increment(1);
                            }
                            Ok(ForkDetectionResult::StaleChain) => {
                                info!(
                                    "Light client chain is stale but valid (included in BDE chain)"
                                );
                                counter!("fork_watchtower.stale_chain_detected").increment(1);
                            }
                            Err(e) => {
                                error!("Error detecting fork: {}", e);
                                counter!("fork_watchtower.fork_detection_error").increment(1);
                            }
                        }
                    }
                }

                ForkWatchtowerEvent::MmrRootUpdated(root) => {
                    info!("Received MMR root update event: {}", hex::encode(root));
                    counter!("fork_watchtower.mmr_root_updated").increment(1);

                    if let Some(resolution) = &pending_resolution {
                        if resolution.expected_mmr_root == root {
                            info!("MMR root update confirmed our fork resolution");
                            counter!("fork_watchtower.resolution_confirmed").increment(1);
                            pending_resolution = None;
                        }
                    }
                }

                ForkWatchtowerEvent::TransactionStatus(status) => {
                    if let Some(resolution) = &mut pending_resolution {
                        if let Some(tx_hash) = &resolution.transaction_hash {
                            if status.tx_hash == *tx_hash {
                                info!("Received status update for our fork resolution transaction");

                                match status.result {
                                    TransactionExecutionResult::Success(receipt) => {
                                        info!(
                                            "Fork resolution transaction successful: {:?}",
                                            receipt
                                        );
                                        counter!("fork_watchtower.transaction_broadcast_success")
                                            .increment(1);

                                    }
                                    TransactionExecutionResult::Revert(revert_info) => {
                                        let should_retry = Self::handle_transaction_revert(
                                            &revert_info,
                                            resolution.expected_mmr_root,
                                        );

                                        if should_retry
                                            && resolution.retries < TRANSACTION_BROADCAST_RETRY_MAX
                                        {
                                            resolution.retries += 1;
                                            resolution.transaction_hash = None;

                                            warn!(
                                                "Transaction reverted with recoverable error, will retry ({}/{})",
                                                resolution.retries, TRANSACTION_BROADCAST_RETRY_MAX
                                            );
                                            counter!("fork_watchtower.transaction_broadcast_retry")
                                                .increment(1);

                                            Self::handle_fork_resolution(
                                                resolution.chain_transition.clone(),
                                                &proof_generator,
                                                &rift_exchange,
                                                &transaction_broadcaster,
                                                &mut pending_resolution,
                                            )
                                            .await;
                                        } else {
                                            error!("Transaction reverted with unrecoverable error: {:?}", revert_info);
                                            counter!("fork_watchtower.transaction_broadcast_unrecoverable_error").increment(1);
                                            pending_resolution = None;
                                        }
                                    }
                                    TransactionExecutionResult::InvalidRequest(msg) => {
                                        error!("Invalid transaction request: {}", msg);
                                        counter!(
                                            "fork_watchtower.transaction_broadcast_invalid_request"
                                        )
                                        .increment(1);
                                        pending_resolution = None;
                                    }
                                    TransactionExecutionResult::UnknownError(msg) => {
                                        if resolution.retries < TRANSACTION_BROADCAST_RETRY_MAX {
                                            resolution.retries += 1;
                                            resolution.transaction_hash = None;

                                            warn!(
                                                "Transaction failed with unknown error, will retry ({}/{}): {}",
                                                resolution.retries, TRANSACTION_BROADCAST_RETRY_MAX, msg
                                            );
                                            counter!("fork_watchtower.transaction_broadcast_unknown_error").increment(1);

                                            Self::handle_fork_resolution(
                                                resolution.chain_transition.clone(),
                                                &proof_generator,
                                                &rift_exchange,
                                                &transaction_broadcaster,
                                                &mut pending_resolution,
                                            )
                                            .await;
                                        } else {
                                            error!("Max retries reached for transaction broadcast");
                                            counter!("fork_watchtower.max_retries_reached")
                                                .increment(1);
                                            pending_resolution = None;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        error!("Event channel closed unexpectedly");
        Err(eyre::eyre!("Event channel closed"))
    }

    pub async fn handle_fork_resolution(
        chain_transition: ChainTransition,
        proof_generator: &Arc<RiftProofGenerator>,
        rift_exchange: &RiftExchangeHarnessInstance<DynProvider>,
        transaction_broadcaster: &Arc<TransactionBroadcaster>,
        pending_resolution: &mut Option<PendingForkResolution>,
    ) {
        match Self::generate_light_client_update_proof(
            chain_transition.clone(),
            Arc::clone(proof_generator),
        )
        .await
        {
            Ok(proof) => {
                info!("Generated proof for fork resolution");

                let (public_values, auxiliary_data) = {
                    let rift_program_input = RiftProgramInput::builder()
                        .proof_type(RustProofType::LightClientOnly)
                        .light_client_input(chain_transition.clone())
                        .build()
                        .map_err(|e| {
                            error!("Failed to build program input: {}", e);
                            return;
                        })
                        .unwrap();

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
                        counter!("fork_watchtower.mock_proof_generated").increment(1);
                        Vec::new()
                    }
                };

                let call =
                    rift_exchange.updateLightClient(block_proof_params.clone(), proof_bytes.into());
                let calldata = call.calldata().to_owned();
                let transaction_request = call.into_transaction_request();

                info!("Broadcasting fork resolution transaction");

                let mut new_resolution = PendingForkResolution {
                    chain_transition,
                    expected_mmr_root: public_values.newMmrRoot.0,
                    transaction_hash: None,
                    retries: 0,
                };

                match Arc::clone(transaction_broadcaster)
                    .broadcast_transaction(calldata, transaction_request, PreflightCheck::Simulate)
                    .await
                {
                    Ok(tx_result) => {
                        if let TransactionExecutionResult::Success(receipt) = &tx_result {
                            new_resolution.transaction_hash = Some(receipt.transaction_hash);
                            info!("Transaction sent: {:?}", receipt.transaction_hash);
                        }
                        *pending_resolution = Some(new_resolution);
                    }
                    Err(e) => {
                        error!("Failed to send transaction: {}", e);
                        counter!("fork_watchtower.transaction_send_error").increment(1);
                    }
                }
            }
            Err(e) => {
                error!("Failed to generate proof: {}", e);
                counter!("fork_watchtower.proof_generation_error").increment(1);
            }
        }
    }

    pub async fn detect_fork(
      contract_data_engine: &Arc<ContractDataEngine>,
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
              message = "No fork - tips match exactly",
              tip_hash = hex::encode(light_client_tip_leaf.block_hash),
          );
          return Ok(ForkDetectionResult::NoFork);
      }
  
      let light_client_chainwork = light_client_tip_leaf.chainwork_as_u256();
      let bitcoin_chainwork = bitcoin_tip_leaf.chainwork_as_u256();
  
      if light_client_chainwork == bitcoin_chainwork {
          info!(
              message = "Tips have equal chainwork, following first-seen policy (no fork)",
              chainwork = format!("{:x}", light_client_chainwork),
          );
          return Ok(ForkDetectionResult::NoFork);
      }
  
      let is_included =
          Self::check_leaf_inclusion_in_bde(&light_client_tip_leaf, &bitcoin_mmr, btc_rpc)
              .await?;
  
      if is_included {
          info!(
              message = "Light client tip is included in BDE chain, no fork needed",
              light_client_tip = hex::encode(light_client_tip_leaf.block_hash),
          );
          return Ok(ForkDetectionResult::StaleChain);
      }

      if light_client_chainwork > bitcoin_chainwork {
          info!(
              message = "Fork detected - light client has block not in BDE chain with higher chainwork",
              light_client_tip = hex::encode(light_client_tip_leaf.block_hash),
              light_client_chainwork = format!("{:x}", light_client_chainwork),
              bitcoin_chainwork = format!("{:x}", bitcoin_chainwork),
          );
      } else {
          info!(
              message = "Fork detected - light client tip not in BDE chain and BDE has more chainwork",
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
            .get_block_header_info(&bitcoincore_rpc_async::bitcoin::BlockHash::from_slice(
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
                              "Found different block at height {} in main chain. Fork detected! Main chain hash: {}, Block hash: {}",
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
                    counter!("fork_watchtower.proof_generation_retry").increment(1);

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

    pub fn handle_transaction_revert(
        revert_info: &RevertInfo,
        expected_mmr_root: [u8; 32],
    ) -> bool {
        info!(
            "Analyzing transaction revert: {:?}, debug command: {}",
            revert_info.error_payload, revert_info.debug_cli_command
        );

        let error_msg = revert_info.error_payload.message.to_lowercase();

        if error_msg.contains("root already exists") || error_msg.contains("mmr root match") {
            info!("MMR root already updated by someone else, no retry needed");
            return false;
        }

        if error_msg.contains("nonce too low")
            || error_msg.contains("nonce too high")
            || error_msg.contains("replacement transaction underpriced")
        {
            info!("Transaction nonce issue, will retry");
            return true;
        }

        if error_msg.contains("gas price")
            || error_msg.contains("max fee")
            || error_msg.contains("gas limit")
        {
            info!("Gas price issue, will retry");
            return true;
        }

        if error_msg.contains("network")
            || error_msg.contains("timeout")
            || error_msg.contains("connection")
        {
            info!("Network issue, will retry");
            return true;
        }

        info!("Unknown revert reason, will attempt retry");
        true
    }
}