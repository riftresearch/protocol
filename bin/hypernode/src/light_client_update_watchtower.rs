use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::DynProvider;
use bitcoin_data_engine::BitcoinDataEngine;
use bitcoin_light_client_core::{hasher::Keccak256Hasher, leaves::BlockLeaf, ChainTransition};
use data_engine::engine::ContractDataEngine;
use rift_core::giga::{RiftProgramInput, RustProofType};
use rift_sdk::bitcoin_utils::AsyncBitcoinClient;
use rift_sdk::proof_generator::{Proof, RiftProofGenerator};
use sol_bindings::{BlockProofParams, RiftExchangeHarnessInstance};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time;
use tracing::{error, info, info_span, warn, Instrument};

use crate::swap_watchtower::build_chain_transition_for_light_client_update;
use rift_sdk::txn_broadcast::{
    PreflightCheck, RevertInfo, TransactionBroadcaster, TransactionExecutionResult,
};

const LIGHT_CLIENT_UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const TRANSACTION_BROADCAST_RETRY_MAX: usize = 5;

#[derive(Debug, Error)]
pub enum LightClientUpdateWatchtowerError {
    #[error("Failed to check light client lag: {0}")]
    LagCheckError(String),

    #[error("Failed to generate light client update proof: {0}")]
    ProofGenerationError(String),

    #[error("Failed to broadcast light client update transaction: {0}")]
    TransactionBroadcastError(String),

    #[error("Failed to build chain transition: {0}")]
    ChainTransitionBuildError(String),

    #[error("Transaction reverted: {0}")]
    TransactionReverted(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<eyre::Report> for LightClientUpdateWatchtowerError {
    fn from(err: eyre::Report) -> Self {
        LightClientUpdateWatchtowerError::Unknown(err.to_string())
    }
}

#[derive(Debug)]
enum LightClientUpdateEvent {
    CheckLag,
    UpdateRequired(u32), // blocks behind
}

pub struct LightClientUpdateWatchtower;

impl LightClientUpdateWatchtower {
    pub async fn run(
        block_lag_threshold: u32,
        check_interval: Duration,
        contract_data_engine: Arc<ContractDataEngine>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        evm_rpc: DynProvider,
        rift_exchange_address: Address,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        bitcoin_concurrency_limit: usize,
        proof_generator: Arc<RiftProofGenerator>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> eyre::Result<Self> {
        info!(
            block_lag_threshold,
            check_interval_secs = check_interval.as_secs(),
            "Starting light client update watchtower"
        );

        let (event_sender, mut event_receiver) = mpsc::channel::<LightClientUpdateEvent>(10);

        let rift_exchange =
            RiftExchangeHarnessInstance::new(rift_exchange_address, evm_rpc.clone());

        // Periodic lag check task
        let event_sender_timer = event_sender.clone();
        join_set.spawn(
            async move {
                let mut interval = time::interval(check_interval);
                interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

                loop {
                    interval.tick().await;
                    if event_sender_timer
                        .send(LightClientUpdateEvent::CheckLag)
                        .await
                        .is_err()
                    {
                        error!("Failed to send lag check event - channel closed");
                        break;
                    }
                }

                Ok(())
            }
            .instrument(info_span!("Light Client Lag Check Timer")),
        );

        // Main event processing task
        join_set.spawn(
            async move {
                while let Some(event) = event_receiver.recv().await {
                    match event {
                        LightClientUpdateEvent::CheckLag => {
                            match Self::check_light_client_lag(
                                &contract_data_engine,
                                &bitcoin_data_engine,
                                block_lag_threshold,
                            )
                            .await
                            {
                                Ok(Some(blocks_behind)) => {
                                    info!(
                                        blocks_behind,
                                        threshold = block_lag_threshold,
                                        "Light client is behind Bitcoin tip - triggering update"
                                    );
                                    if event_sender
                                        .send(LightClientUpdateEvent::UpdateRequired(blocks_behind))
                                        .await
                                        .is_err()
                                    {
                                        error!("Failed to send update required event");
                                        break;
                                    }
                                }
                                Ok(None) => {
                                    // Light client is up to date
                                }
                                Err(e) => {
                                    error!("Failed to check light client lag: {}", e);
                                }
                            }
                        }
                        LightClientUpdateEvent::UpdateRequired(blocks_behind) => {
                            if let Err(e) = Self::perform_light_client_update(
                                &contract_data_engine,
                                &bitcoin_data_engine,
                                &btc_rpc,
                                &rift_exchange,
                                &transaction_broadcaster,
                                bitcoin_concurrency_limit,
                                &proof_generator,
                                blocks_behind,
                            )
                            .await
                            {
                                error!("Failed to perform light client update: {}", e);
                            }
                        }
                    }
                }

                Ok(())
            }
            .instrument(info_span!("Light Client Update Event Handler")),
        );

        Ok(Self)
    }

    /// Check if the light client is lagging behind Bitcoin tip by more than the threshold
    /// Returns Some(blocks_behind) if update is needed, None if up to date
    async fn check_light_client_lag(
        contract_data_engine: &Arc<ContractDataEngine>,
        bitcoin_data_engine: &Arc<BitcoinDataEngine>,
        block_lag_threshold: u32,
    ) -> Result<Option<u32>, LightClientUpdateWatchtowerError> {
        // Get current light client tip from contract data engine
        let light_client_mmr_guard = contract_data_engine.checkpointed_block_tree.read().await;
        let light_client_leaf_count =
            light_client_mmr_guard.get_leaf_count().await.map_err(|e| {
                LightClientUpdateWatchtowerError::LagCheckError(format!(
                    "Failed to get light client leaf count: {}",
                    e
                ))
            })?;

        if light_client_leaf_count == 0 {
            return Err(LightClientUpdateWatchtowerError::LagCheckError(
                "Light client MMR has no leaves".to_string(),
            ));
        }

        let light_client_tip = light_client_mmr_guard
            .get_leaf_by_leaf_index(light_client_leaf_count - 1)
            .await
            .map_err(|e| {
                LightClientUpdateWatchtowerError::LagCheckError(format!(
                    "Failed to get light client tip: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                LightClientUpdateWatchtowerError::LagCheckError(
                    "Light client tip not found".to_string(),
                )
            })?;
        drop(light_client_mmr_guard);

        // Get current Bitcoin tip from bitcoin data engine
        let bitcoin_mmr_guard = bitcoin_data_engine.indexed_mmr.read().await;
        let bitcoin_leaf_count = bitcoin_mmr_guard.get_leaf_count().await.map_err(|e| {
            LightClientUpdateWatchtowerError::LagCheckError(format!(
                "Failed to get bitcoin leaf count: {}",
                e
            ))
        })?;

        if bitcoin_leaf_count == 0 {
            return Err(LightClientUpdateWatchtowerError::LagCheckError(
                "Bitcoin MMR has no leaves".to_string(),
            ));
        }

        let bitcoin_tip = bitcoin_mmr_guard
            .get_leaf_by_leaf_index(bitcoin_leaf_count - 1)
            .await
            .map_err(|e| {
                LightClientUpdateWatchtowerError::LagCheckError(format!(
                    "Failed to get bitcoin tip: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                LightClientUpdateWatchtowerError::LagCheckError("Bitcoin tip not found".to_string())
            })?;
        drop(bitcoin_mmr_guard);

        // Calculate block height difference
        let light_client_height = light_client_tip.height;
        let bitcoin_height = bitcoin_tip.height;

        if bitcoin_height <= light_client_height {
            // Light client is up to date or ahead (shouldn't happen)
            return Ok(None);
        }

        let blocks_behind = bitcoin_height - light_client_height;

        if blocks_behind >= block_lag_threshold {
            Ok(Some(blocks_behind))
        } else {
            Ok(None)
        }
    }

    /// Perform the light client update by generating and submitting a proof
    async fn perform_light_client_update(
        contract_data_engine: &Arc<ContractDataEngine>,
        bitcoin_data_engine: &Arc<BitcoinDataEngine>,
        btc_rpc: &Arc<AsyncBitcoinClient>,
        rift_exchange: &RiftExchangeHarnessInstance<DynProvider>,
        transaction_broadcaster: &Arc<TransactionBroadcaster>,
        bitcoin_concurrency_limit: usize,
        proof_generator: &Arc<RiftProofGenerator>,
        blocks_behind: u32,
    ) -> Result<(), LightClientUpdateWatchtowerError> {
        info!(blocks_behind, "Starting light client update process");

        // Build chain transition for light client update
        let light_client_mmr = contract_data_engine.checkpointed_block_tree.read().await;
        let bitcoin_mmr = bitcoin_data_engine.indexed_mmr.read().await;

        let chain_transition = build_chain_transition_for_light_client_update(
            btc_rpc.clone(),
            &bitcoin_mmr,
            &light_client_mmr,
            bitcoin_concurrency_limit,
        )
        .await
        .map_err(|e| {
            LightClientUpdateWatchtowerError::ChainTransitionBuildError(format!(
                "Failed to build chain transition: {}",
                e
            ))
        })?;

        info!(
            new_headers_count = chain_transition.new_headers.len(),
            "Built chain transition for light client update"
        );

        // Generate proof for the chain transition
        let proof =
            Self::generate_light_client_update_proof(&chain_transition, proof_generator).await?;

        // Generate auxiliary data from chain transition for the proof
        let (public_input, auxiliary_data_option) =
            chain_transition.verify::<Keccak256Hasher>(true);

        let auxiliary_data = auxiliary_data_option.ok_or_else(|| {
            LightClientUpdateWatchtowerError::ChainTransitionBuildError(
                "Failed to generate auxiliary data from chain transition".to_string(),
            )
        })?;

        // Prepare transaction parameters
        let block_proof_params = BlockProofParams {
            priorMmrRoot: public_input.priorMmrRoot.into(),
            newMmrRoot: public_input.newMmrRoot.into(),
            tipBlockLeaf: public_input.tipBlockLeaf,
            compressedBlockLeaves: auxiliary_data.compressed_leaves.into(),
        };

        // Submit the light client update transaction
        Self::submit_light_client_update(
            rift_exchange,
            transaction_broadcaster,
            block_proof_params,
            proof,
        )
        .await?;

        info!(blocks_behind, "Successfully submitted light client update");

        Ok(())
    }

    /// Generate a zero-knowledge proof for the light client update
    async fn generate_light_client_update_proof(
        chain_transition: &ChainTransition,
        proof_generator: &Arc<RiftProofGenerator>,
    ) -> Result<Proof, LightClientUpdateWatchtowerError> {
        let input = RiftProgramInput {
            proof_type: RustProofType::LightClientOnly,
            light_client_input: Some(chain_transition.clone()),
            order_filling_transaction_input: None,
        };

        let proof = proof_generator.prove(&input).await.map_err(|e| {
            LightClientUpdateWatchtowerError::ProofGenerationError(format!(
                "Failed to generate light client update proof: {}",
                e
            ))
        })?;

        Ok(proof)
    }

    /// Submit the light client update transaction to the Ethereum network
    async fn submit_light_client_update(
        rift_exchange: &RiftExchangeHarnessInstance<DynProvider>,
        transaction_broadcaster: &Arc<TransactionBroadcaster>,
        block_proof_params: BlockProofParams,
        proof: Proof,
    ) -> Result<(), LightClientUpdateWatchtowerError> {
        let proof_bytes = match &proof.proof {
            Some(p) => p.bytes(),
            None => {
                warn!("Using mock proof for light client update");
                Vec::new()
            }
        };

        let call = rift_exchange.updateLightClient(block_proof_params, proof_bytes.into());
        let calldata = call.calldata().to_owned();
        let transaction_request = call.into_transaction_request();

        // Broadcast the transaction with retry logic
        for attempt in 1..=TRANSACTION_BROADCAST_RETRY_MAX {
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
                        tx_hash = format!("{:?}", receipt.transaction_hash),
                        block_number = receipt.block_number,
                        "Light client update transaction confirmed"
                    );
                    return Ok(());
                }
                Ok(TransactionExecutionResult::Revert(revert_info)) => {
                    return Err(LightClientUpdateWatchtowerError::TransactionReverted(
                        format!("Transaction reverted: {:?}", revert_info),
                    ));
                }
                Ok(TransactionExecutionResult::InvalidRequest(msg)) => {
                    return Err(LightClientUpdateWatchtowerError::TransactionBroadcastError(
                        format!("Invalid request: {}", msg),
                    ));
                }
                Ok(TransactionExecutionResult::UnknownError(msg)) => {
                    return Err(LightClientUpdateWatchtowerError::TransactionBroadcastError(
                        format!("Unknown error: {}", msg),
                    ));
                }
                Err(e) => {
                    warn!(
                        attempt,
                        max_attempts = TRANSACTION_BROADCAST_RETRY_MAX,
                        error = %e,
                        "Light client update transaction broadcast failed"
                    );

                    if attempt == TRANSACTION_BROADCAST_RETRY_MAX {
                        return Err(LightClientUpdateWatchtowerError::TransactionBroadcastError(
                            format!("Failed after {} attempts: {}", attempt, e),
                        ));
                    }

                    // Exponential backoff delay
                    let delay = Duration::from_secs(2u64.pow(attempt as u32 - 1));
                    time::sleep(delay).await;
                }
            }
        }

        unreachable!()
    }
}
