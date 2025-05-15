use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::{Filter, Log};
use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{SolEvent, SolValue};
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use data_engine::{engine::ContractDataEngine, models::ChainAwareOrder};
use eyre::{eyre, Result};
use log::{debug, error, info, warn};
use rift_sdk::checkpoint_mmr::CheckpointedBlockTree;
use rift_sdk::create_websocket_wallet_provider;
use rift_sdk::fee_provider::BtcFeeProvider;
use rift_sdk::txn_broadcast::{PreflightCheck, TransactionBroadcaster, TransactionExecutionResult};
use sol_bindings::BTCDutchAuctionHouse::BlockLeaf;
use sol_bindings::{
    AuctionUpdated, BTCDutchAuctionHouseInstance, BitcoinLightClientInstance, DutchAuction,
    MappingWhitelistInstance,
};
use std::{cmp::Reverse, collections::BinaryHeap, sync::Arc};
use tokio::{
    sync::{mpsc, Mutex, RwLock},
    task::JoinSet,
};

#[derive(Debug, Clone)]
pub struct PendingAuction {
    pub auction: DutchAuction,
    pub claim_at_block: u64,
}

impl PartialEq for PendingAuction {
    fn eq(&self, other: &Self) -> bool {
        self.claim_at_block == other.claim_at_block
    }
}

impl Eq for PendingAuction {}

impl PartialOrd for PendingAuction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingAuction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.claim_at_block.cmp(&other.claim_at_block)
    }
}

#[derive(Clone)]
pub struct AuctionClaimerConfig {
    pub auction_house_address: Address,
    pub market_maker_address: Address,
    pub spread_bps: u64,
    pub btc_fee_provider: Arc<dyn BtcFeeProvider>,
    pub eth_gas_fee_sats: u64,
    pub max_batch_size: usize,
    pub evm_ws_rpc: String,
}

/// Finds best block to claim an auction for profit
pub async fn calculate_optimal_claim_block(
    auction: &DutchAuction,
    spread_bps: u64,
    btc_fee_provider: Arc<dyn BtcFeeProvider>,
    eth_gas_fee_sats: u64,
    current_block: u64,
) -> Option<u64> {
    if spread_bps == 0 {
        debug!("Invalid spread bps: #{}", spread_bps);
        return None;
    }

    let btc_fee_sats = btc_fee_provider.get_fee_rate_sats_per_vb().await;

    // Get auction parameters
    let start_btc_out_f64 = u128::try_from(auction.dutchAuctionParams.startBtcOut)
        .expect("U256 to u128 conversion failed for startBtcOut")
        as f64;
    let end_btc_out_f64 = u128::try_from(auction.dutchAuctionParams.endBtcOut)
        .expect("U256 to u128 conversion failed for endBtcOut") as f64;
    let deposit_amount_f64 = u128::try_from(auction.depositAmount)
        .expect("U256 to u128 conversion failed for depositAmount")
        as f64;

    let decay_blocks: u64 = auction
        .dutchAuctionParams
        .decayBlocks
        .try_into()
        .unwrap_or(0);
    let start_block = u64::try_from(auction.startBlock).ok()?;
    let deadline = u64::try_from(auction.dutchAuctionParams.deadline).unwrap_or(u64::MAX);

    // Skip if expired
    if current_block >= deadline {
        debug!("Auction #{} has expired", auction.index);
        return None;
    }

    let spread_bps_f64 = spread_bps as f64;
    let btc_fee_sats_f64 = btc_fee_sats as f64;
    let eth_gas_fee_sats_f64 = eth_gas_fee_sats as f64;
    let redemption_fee_f64 = 0.0; // 0 for cbBTC

    // Synthetic BTC is deposit amount
    let synthetic_btc_f64 = deposit_amount_f64;

    // Calculate max BTC we'd send
    // sentSats_max = (sBTC - 2f_btc - f_eth - r(sBTC)) / (1 + s/10^4)
    let double_btc_fee_f64 = btc_fee_sats_f64 * 2.0;
    let numerator_f64 =
        synthetic_btc_f64 - double_btc_fee_f64 - eth_gas_fee_sats_f64 - redemption_fee_f64;

    let spread_factor_f64 = spread_bps_f64 / 10000.0;
    let denominator_f64 = 1.0 + spread_factor_f64;

    const EPSILON: f64 = 1e-9;

    // Check for division by zero/near-zero
    if denominator_f64.abs() < EPSILON {
        error!(
            "Calculation error: Denominator zero with spread {}",
            spread_bps
        );
        return None;
    }

    if numerator_f64 < 0.0 {
        // cant send negative sats
        debug!(
            "Auction #{} not profitable due to fees exceeding deposit: numerator_f64 = {}",
            auction.index, numerator_f64
        );
        return None;
    }

    let max_sent_sats_f64 = numerator_f64 / denominator_f64;

    // if max_sent_sats is negative (e.g. fees > deposit), it's not profitable or just super small
    if max_sent_sats_f64 <= 0.0 {
        debug!(
            "Auction #{} not profitable: max_sent_sats_f64 ({}) <= 0.0",
            auction.index, max_sent_sats_f64
        );
        return None;
    }

    // If below end amount, never profitable
    if max_sent_sats_f64 < end_btc_out_f64 {
        debug!(
            "Auction #{} never profitable: max_sent_sats_f64 ({}) < end_btc_out_f64 ({})",
            auction.index, max_sent_sats_f64, end_btc_out_f64
        );
        return None;
    }

    // If above start amount, profitable now
    if max_sent_sats_f64 >= start_btc_out_f64 {
        debug!(
            "Auction #{} profitable immediately: max_sent_sats_f64 ({}) >= start_btc_out_f64 ({})",
            auction.index, max_sent_sats_f64, start_btc_out_f64
        );
        return Some(current_block.max(start_block));
    }

    // No decay = no future profitability
    if decay_blocks == 0 {
        debug!(
            "Auction #{} not profitable: decay_blocks is 0 and not profitable at start price.",
            auction.index
        );
        return None;
    }

    // Find optimal with decay formula

    // t(a) = t_0 + (t_1 - t_0)(a - a_0)/(a_1 - a_0)

    let t_0 = start_block;
    let t_1 = start_block + decay_blocks;
    let a_0_f64 = start_btc_out_f64;
    let a_1_f64 = end_btc_out_f64;
    let a_f64 = max_sent_sats_f64;

    let btc_price_decay_range_f64 = a_0_f64 - a_1_f64;

    if btc_price_decay_range_f64 <= EPSILON {
        debug!(
            "Auction #{} has no effective price decay or inverted prices: start_btc_out_f64={}, end_btc_out_f64={}",
            auction.index, a_0_f64, a_1_f64
        );
        return None;
    }

    let price_diff_to_target_f64 = a_0_f64 - a_f64;
    if price_diff_to_target_f64 < 0.0 {
        error!(
            "Unexpected state in auction #{}: max_sent_sats_f64 ({}) > start_btc_out_f64 ({})",
            auction.index, a_f64, a_0_f64
        );
        return None;
    }

    let block_offset_f64 =
        (decay_blocks as f64) * (price_diff_to_target_f64 / btc_price_decay_range_f64);

    // Calculate block offset
    let optimal_block_f64 = (t_0 as f64) + block_offset_f64;
    let optimal_block = optimal_block_f64.ceil() as u64;

    // Get optimal block
    let optimal_block = optimal_block.max(start_block).max(current_block);

    // Check deadline
    if optimal_block >= deadline {
        debug!(
            "Optimal block {} (raw_optimal {}, start_block {}, current_block {}) is at or after deadline {}",
            optimal_block, optimal_block, start_block, current_block, deadline
        );
        return None;
    }

    Some(optimal_block)
}

/// Extract auction data from a log
pub fn extract_auction_from_log(log: &Log) -> Result<DutchAuction> {
    let decoded = AuctionUpdated::decode_log(&log.inner)
        .map_err(|e| eyre!("Failed to decode AuctionUpdated event: {:?}", e))?;

    let auction = decoded.auction.clone();

    debug!("Decoded auction from log: index={}", auction.index);

    Ok(auction)
}

pub struct AuctionClaimer {}

impl AuctionClaimer {
    /// Start listening for auctions and process them
    pub async fn run(
        provider: DynProvider,
        config: AuctionClaimerConfig,
        contract_data_engine: Arc<ContractDataEngine>,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<()> {
        // Setup channel for auction claiming
        let (auction_tx, mut auction_rx) = mpsc::channel(100);
        let pending_auctions = Arc::new(Mutex::new(BinaryHeap::new()));

        let provider_for_listener = provider.clone();
        let config_for_listener = config.clone();
        let pending_auctions_for_listener = pending_auctions.clone();
        let auction_tx_for_listener = auction_tx.clone();
        let contract_data_engine = contract_data_engine.clone();
        let transaction_broadcaster_for_listener = transaction_broadcaster.clone();

        join_set.spawn(async move {
            info!("Starting event listener task");

            let filter = Filter::new()
                .address(config_for_listener.auction_house_address)
                .event(AuctionUpdated::SIGNATURE);

            // Subscribe to new events
            let mut subscription = match provider_for_listener.subscribe_logs(&filter).await {
                Ok(sub) => {
                    info!("Successfully subscribed to AuctionUpdated events");
                    sub
                }
                Err(e) => {
                    error!("Failed to subscribe to AuctionUpdated events: {:?}", e);
                    return Err(eyre::eyre!("Event listener task failed: {}", e));
                }
            };

            // Process events as they arrive
            loop {
                match subscription.recv().await {
                    Ok(log) => {
                        debug!("Received new AuctionUpdated event");
                        if let Err(e) = Self::process_auction_event(
                            provider_for_listener.clone(),
                            pending_auctions_for_listener.clone(),
                            config_for_listener.clone(),
                            log,
                            auction_tx_for_listener.clone(),
                        )
                        .await
                        {
                            error!("Error processing new auction event: {:?}", e);
                        }
                    }
                    Err(e) => {
                        error!("Error receiving log: {:?}", e);
                        break;
                    }
                }
            }

            Ok(())
        });

        // Block processor task
        let provider_for_processor = provider.clone();
        let pending_auctions_for_processor = pending_auctions.clone();
        let config_for_processor = config.clone();
        let auction_tx_for_processor = auction_tx.clone();
        join_set.spawn(async move {
            info!("Starting block processor task");

            // Subscribe to new blocks
            let mut block_subscription = match provider_for_processor.subscribe_blocks().await {
                Ok(sub) => {
                    info!("Successfully subscribed to new blocks");
                    sub
                }
                Err(e) => {
                    error!("Failed to subscribe to new blocks: {:?}", e);
                    return Err(eyre::eyre!(
                        "Block processor task failed to start subscription: {}",
                        e
                    ));
                }
            };

            // Process new blocks
            loop {
                match block_subscription.recv().await {
                    Ok(block) => {
                        let current_block = block.number;
                        debug!("New block received: {}", current_block);

                        // Process pending auctions
                        if let Err(e) = Self::process_pending_auctions(
                            provider_for_processor.clone(),
                            pending_auctions_for_processor.clone(),
                            current_block,
                            config_for_processor.max_batch_size,
                            auction_tx_for_processor.clone(),
                            config_for_processor.clone(),
                        )
                        .await
                        {
                            error!("Error processing pending auctions: {:?}", e);
                        }
                    }
                    Err(e) => {
                        error!("Error receiving block: {:?}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });

        // Claim auctions task
        let config_for_claimer = config.clone();
        let provider_for_claimer = provider.clone();
        let contract_data_engine_for_claimer = contract_data_engine.clone();
        let transaction_broadcaster_for_claimer = transaction_broadcaster.clone();
        join_set.spawn(async move {
            info!("Starting auction claimer task");

            while let Some((auction, claim_block)) = auction_rx.recv().await {
                info!(
                    "Claiming auction #{} at block {}",
                    auction.index, claim_block
                );

                let auction_house_instance = BTCDutchAuctionHouseInstance::new(
                    config_for_claimer.auction_house_address,
                    provider_for_claimer.clone(),
                );

                // Check if auction is still valid
                if auction.state != 0 {
                    info!(
                        "Skipping auction #{} as it's no longer claimable",
                        auction.index
                    );
                    continue;
                }

                // Check whitelist requirements
                if auction.dutchAuctionParams.fillerWhitelistContract != Address::ZERO {
                    let whitelist_contract_address =
                        auction.dutchAuctionParams.fillerWhitelistContract;

                    let whitelist_instance = MappingWhitelistInstance::new(
                        whitelist_contract_address,
                        provider_for_claimer.clone(),
                    );

                    // Check if maker is whitelisted
                    let is_whitelisted = match whitelist_instance
                        .isWhitelisted(config_for_claimer.market_maker_address, Bytes::new())
                        .call()
                        .await
                    {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Error checking whitelist: {:?}", e);
                            false
                        }
                    };

                    if !is_whitelisted {
                        // Not for us, skip
                        continue;
                    }
                }

                // Prepare claim parameters
                let filler_auth_data = Bytes::new();

                // Get Merkle proof
                let (leaf, siblings, peaks) = contract_data_engine_for_claimer
                    .get_tip_proof()
                    .await
                    .unwrap();

                // Claim the auction
                let claim_call = auction_house_instance.claimAuction(
                    auction.clone(),
                    filler_auth_data.clone(),
                    siblings.into_iter().map(FixedBytes::from).collect(),
                    peaks.into_iter().map(FixedBytes::from).collect(),
                );

                let calldata = claim_call.calldata();

                let tx_request = claim_call
                    .clone()
                    .from(config_for_claimer.market_maker_address)
                    .into_transaction_request();

                info!("Attempting to claim auction #{}", auction.index);

                let claim_broadcast_result = transaction_broadcaster_for_claimer
                    .broadcast_transaction(
                        calldata.clone(),
                        tx_request.clone(),
                        PreflightCheck::Simulate,
                    )
                    .await;

                match claim_broadcast_result {
                    Ok(execution_result) => match execution_result {
                        TransactionExecutionResult::Success(receipt) => {
                            info!(
                                "Successfully claimed auction #{}: tx_hash {}",
                                auction.index, receipt.transaction_hash
                            );
                        }
                        TransactionExecutionResult::Revert(revert_info) => {
                            error!(
                                "Claiming auction #{} reverted: {:?} - debug command: {}",
                                auction.index,
                                revert_info.error_payload,
                                revert_info.debug_cli_command
                            );
                        }
                        TransactionExecutionResult::InvalidRequest(msg) => {
                            error!(
                                "Invalid request for claiming auction #{}: {}",
                                auction.index, msg
                            );
                        }
                        TransactionExecutionResult::UnknownError(msg) => {
                            error!("Unknown error claiming auction #{}: {}", auction.index, msg);
                        }
                    },
                    Err(e) => {
                        error!(
                            "Error broadcasting claim for auction #{}: {:?}",
                            auction.index, e
                        );
                    }
                }
            }
            Ok(())
        });

        Ok(())
    }

    /// Process an AuctionUpdated event
    pub async fn process_auction_event(
        provider: DynProvider,
        pending_auctions: Arc<Mutex<BinaryHeap<Reverse<PendingAuction>>>>,
        config: AuctionClaimerConfig,
        log: Log,
        _auction_tx: mpsc::Sender<(DutchAuction, u64)>,
    ) -> Result<()> {
        match extract_auction_from_log(&log) {
            Ok(auction) => {
                // Handle Created state auctions
                if auction.state == 0 {
                    // Check whitelist if needed
                    if auction.dutchAuctionParams.fillerWhitelistContract != Address::ZERO {
                        let whitelist_address = auction.dutchAuctionParams.fillerWhitelistContract;

                        let whitelist_instance =
                            MappingWhitelistInstance::new(whitelist_address, provider.clone());

                        let is_whitelisted = match whitelist_instance
                            .isWhitelisted(config.market_maker_address, Bytes::new())
                            .call()
                            .await
                        {
                            Ok(result) => result,
                            Err(e) => {
                                error!("Error checking whitelist: {:?}", e);
                                false
                            }
                        };

                        if !is_whitelisted {
                            return Ok(());
                        }
                    }

                    // Check if profitable to claim
                    if let Some(claim_block) = calculate_optimal_claim_block(
                        &auction,
                        config.spread_bps,
                        config.btc_fee_provider.clone(),
                        config.eth_gas_fee_sats,
                        (provider.get_block_number().await).unwrap_or(0),
                    )
                    .await
                    {
                        // Add to pending queue
                        let pending_auction = PendingAuction {
                            auction: auction.clone(),
                            claim_at_block: claim_block,
                        };

                        let mut auctions = pending_auctions.lock().await;
                        auctions.push(Reverse(pending_auction));

                        info!(
                            "Added auction #{} to pending queue, will claim at block {}",
                            auction.index, claim_block
                        );
                    } else {
                        info!("Auction #{} is not profitable, skipping", auction.index);
                    }
                } else {
                    info!(
                        "Auction #{} received with state {}",
                        auction.index, auction.state
                    );
                }
            }
            Err(e) => {
                error!("Failed to extract auction from log: {:?}", e);
            }
        }
        Ok(())
    }

    /// Process auctions ready to be claimed
    pub async fn process_pending_auctions(
        provider: DynProvider,
        pending_auctions: Arc<Mutex<BinaryHeap<Reverse<PendingAuction>>>>,
        current_block: u64,
        max_batch_size: usize,
        auction_tx: mpsc::Sender<(DutchAuction, u64)>,
        config: AuctionClaimerConfig,
    ) -> Result<()> {
        let mut auctions_to_verify = Vec::new();
        {
            let mut auctions = pending_auctions.lock().await;

            while let Some(Reverse(pending)) = auctions.peek() {
                if pending.claim_at_block <= current_block {
                    if let Some(Reverse(auction)) = auctions.pop() {
                        auctions_to_verify.push(auction);

                        // Process in batches
                        if auctions_to_verify.len() >= max_batch_size {
                            break;
                        }
                    }
                } else {
                    // Rest are for future blocks
                    break;
                }
            }
        }

        // Verify each auction before claiming
        let mut auctions_to_claim = Vec::new();

        for pending in auctions_to_verify {
            // Make sure auction is still valid
            if pending.auction.state != 0 {
                info!(
                    "Skipping auction #{} - no longer claimable",
                    pending.auction.index
                );
                continue;
            } else {
                auctions_to_claim.push(pending);
            }
        }

        // Send valid auctions to be claimed
        for pending in auctions_to_claim {
            info!(
                "Sending auction #{} to claim at block {}",
                pending.auction.index, pending.claim_at_block
            );

            if let Err(e) = auction_tx
                .send((pending.auction, pending.claim_at_block))
                .await
            {
                error!("Failed to send auction for claiming: {:?}", e);
            }
        }

        Ok(())
    }
}
