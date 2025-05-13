use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::{Filter, Log};
use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{SolEvent, SolValue};
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use eyre::{eyre, Result};
use log::{debug, error, info, warn};
use rift_sdk::checkpoint_mmr::CheckpointedBlockTree;
use rift_sdk::create_websocket_wallet_provider;
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

#[derive(Clone, Debug)]
pub struct AuctionClaimerConfig {
    pub auction_house_address: Address,
    pub market_maker_address: Address,
    pub spread_bps: u64,
    pub btc_fee_sats: u64,
    pub eth_gas_fee_sats: u64,
    pub max_batch_size: usize,
    pub evm_ws_rpc: String,
    pub light_client_address: Option<Address>,
}
pub trait BTCDutchAuctionHouseContractTrait {
    async fn claim_auction(
        &self,
        _auction: DutchAuction,
        _filler_auth_data: Bytes,
        _safe_block_siblings: Vec<FixedBytes<32>>,
        _safe_block_peaks: Vec<FixedBytes<32>>,
    ) -> Result<FixedBytes<32>>;
}

/// Finds best block to claim an auction for profit
pub fn calculate_optimal_claim_block(
    auction: &DutchAuction,
    spread_bps: u64,
    btc_fee_sats: u64,
    eth_gas_fee_sats: u64,
    current_block: u64,
) -> Option<u64> {
    if spread_bps == 0 {
        debug!("Invalid spread bps: #{}", spread_bps);
        return None;
    }

    // Get auction parameters
    let start_btc_out = auction.dutchAuctionParams.startBtcOut;
    let end_btc_out = auction.dutchAuctionParams.endBtcOut;
    let decay_blocks: u64 = auction
        .dutchAuctionParams
        .decayBlocks
        .try_into()
        .unwrap_or(0);
    let deposit_amount = auction.depositAmount;
    let start_block = u64::try_from(auction.startBlock).ok()?;
    let deadline = u64::try_from(auction.dutchAuctionParams.deadline).unwrap_or(u64::MAX);

    // Skip if expired
    if current_block >= deadline {
        debug!("Auction #{} has expired", auction.index);
        return None;
    }

    let spread = U256::from(spread_bps);
    let btc_fee = U256::from(btc_fee_sats);
    let eth_fee = U256::from(eth_gas_fee_sats);
    let redemption_fee = U256::from(0); // 0 for cbBTC

    // Synthetic BTC is deposit amount
    let synthetic_btc = deposit_amount;

    // Calculate max BTC we'd send
    // sentSats_max = (sBTC - 2f_btc - f_eth - r(sBTC)) / (1 + s/10^4)
    let double_btc_fee = btc_fee.saturating_mul(U256::from(2));
    let numerator = synthetic_btc
        .saturating_sub(double_btc_fee)
        .saturating_sub(eth_fee)
        .saturating_sub(redemption_fee);

    let spread_factor = spread.checked_div(U256::from(10000)).unwrap_or(U256::ZERO);
    let denominator = U256::from(1).saturating_add(spread_factor);

    // Check for division by zero
    if denominator.is_zero() {
        error!(
            "Calculation error: Denominator zero with spread {}",
            spread_bps
        );
        return None;
    }

    let max_sent_sats = numerator.checked_div(denominator).unwrap_or(U256::ZERO);

    // If below end amount, never profitable
    if max_sent_sats < end_btc_out {
        debug!(
            "Auction #{} never profitable: max_sent_sats < end_btc_out",
            auction.index
        );
        return None;
    }

    // If above start amount, profitable now
    if max_sent_sats >= start_btc_out {
        debug!("Auction #{} profitable immediately", auction.index);
        return Some(current_block.max(start_block));
    }

    // No decay = no future profitability
    if decay_blocks == 0 {
        return None;
    }

    // Find optimal with decay formula
    // t(a) = t_0 + (t_1 - t_0)(a - a_0)/(a_1 - a_0)
    let t_0 = start_block;
    let t_1 = start_block + decay_blocks;
    let a_0 = start_btc_out;
    let a_1 = end_btc_out;
    let a = max_sent_sats;

    // Check range
    if a < a_0 || a > a_1 {
        return None;
    }

    // Calculate block delta
    let block_delta = match t_1.checked_sub(t_0) {
        Some(delta) => delta,
        None => {
            error!(
                "Auction #{} invalid block range: start={}, end={}",
                auction.index, t_0, t_1
            );
            return None;
        }
    };

    // Check for meaningful price decay
    let btc_diff = match a_0.checked_sub(a_1) {
        Some(diff) if !diff.is_zero() => diff,
        _ => {
            debug!(
                "Auction #{} has no price decay: start={}, end={}",
                auction.index, a_0, a_1
            );
            return if max_sent_sats >= a_0 {
                Some(t_0)
            } else {
                None
            };
        }
    };

    // How far max_sent_sats is from start
    let a_diff = match a_0.checked_sub(a) {
        Some(diff) => diff,
        None => {
            error!("Unexpected in auction #{}: a > a_0", auction.index);
            return None;
        }
    };

    // Calculate block offset
    let block_offset = (U256::from(block_delta)
        .saturating_mul(a_diff)
        .checked_div(btc_diff))
    .unwrap_or(U256::ZERO)
    .try_into()
    .unwrap_or(0);

    // Get optimal block
    let optimal_block = t_0.saturating_add(block_offset);

    // Check deadline
    if optimal_block >= deadline {
        debug!(
            "Optimal block {} beyond deadline {}",
            optimal_block, deadline
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

pub struct AuctionClaimer {
    pub evm_ws_rpc: String,
    pub private_key: String,
    /// Claimer config
    config: AuctionClaimerConfig,
    /// Optional contract data engine for Merkle proofs
    contract_data_engine: Option<Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>>,
}

impl AuctionClaimer {
    /// Create new AuctionClaimer
    pub fn new(
        evm_ws_rpc: String,
        private_key: String,
        config: AuctionClaimerConfig,
        contract_data_engine: Option<Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>>,
    ) -> Self {
        Self {
            evm_ws_rpc,
            private_key,
            config,
            contract_data_engine,
        }
    }

    /// Start listening for auctions and process them
    pub async fn run(&self) -> Result<()> {
        let mut join_set = JoinSet::new();
        // Setup channel for auction claiming
        let (auction_tx, mut auction_rx) = mpsc::channel(100);
        let pending_auctions = Arc::new(Mutex::new(BinaryHeap::new()));

        let evm_rpc_with_wallet = Arc::new(
            create_websocket_wallet_provider(
                &self.evm_ws_rpc,
                hex::decode(&self.private_key)
                    .map_err(|e| eyre::eyre!(e))?
                    .try_into()
                    .map_err(|_| eyre::eyre!("Invalid private key length"))?,
            )
            .await?,
        );

        let provider = evm_rpc_with_wallet.clone().erased();

        let provider_for_listener = provider.clone();
        let config_for_listener = self.config.clone();
        let pending_auctions_for_listener = pending_auctions.clone();
        let auction_tx_for_listener = auction_tx.clone();
        let contract_data_engine = self.contract_data_engine.clone();

        join_set.spawn(async move {
            info!("Starting event listener task");

            let filter = Filter::new()
                .address(config_for_listener.auction_house_address)
                .event(AuctionUpdated::SIGNATURE);

            // Get historical logs
            match provider_for_listener.get_logs(&filter).await {
                Ok(logs) => {
                    info!("Fetched {} historical auction events", logs.len());
                    for log in logs {
                        if let Err(e) = Self::process_auction_event(
                            provider_for_listener.clone(),
                            pending_auctions_for_listener.clone(),
                            config_for_listener.clone(),
                            log,
                            auction_tx_for_listener.clone(),
                        )
                        .await
                        {
                            error!("Error processing historical auction event: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to fetch historical auction events: {:?}", e);
                }
            }

            // Subscribe to new events
            let mut subscription = match provider_for_listener.subscribe_logs(&filter).await {
                Ok(sub) => {
                    info!("Successfully subscribed to AuctionUpdated events");
                    sub
                }
                Err(e) => {
                    error!("Failed to subscribe to AuctionUpdated events: {:?}", e);
                    return "Event listener task failed";
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

            "Event listener task completed"
        });

        // Block processor task
        let provider_for_processor = provider.clone();
        let pending_auctions_for_processor = pending_auctions.clone();
        let config_for_processor = self.config.clone();
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
                    return "Block processor task failed to start subscription";
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
        let config_for_claimer = self.config.clone();
        let provider_for_claimer = provider.clone();
        let contract_data_engine_for_claimer = contract_data_engine;
        join_set.spawn(async move {
            info!("Starting auction claimer task");

            // Create auction claimer reference
            let auction_claimer = Arc::new(AuctionClaimer::new(
                config_for_claimer.evm_ws_rpc.clone(),
                "".to_string(), // TODO: Add private key
                config_for_claimer.clone(),
                contract_data_engine_for_claimer,
            ));

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
                match Self::verify_auction_state(
                    provider_for_claimer.clone(),
                    &config_for_claimer,
                    &auction,
                )
                .await
                {
                    Ok(is_valid) => {
                        if !is_valid {
                            info!(
                                "Skipping auction #{} as it's no longer claimable",
                                auction.index
                            );
                            continue;
                        }
                    }
                    Err(e) => {
                        error!("Error verifying auction #{}: {:?}", auction.index, e);
                        continue;
                    }
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
                let (siblings, peaks) = match auction_claimer
                    .get_merkle_proof_for_auction(provider_for_claimer.clone(), &auction)
                    .await
                {
                    Ok(proof) => proof,
                    Err(e) => {
                        error!(
                            "Error getting Merkle proof for auction #{}: {:?}",
                            auction.index, e
                        );
                        continue;
                    }
                };

                // Claim the auction
                let claim_result = auction_house_instance
                    .claimAuction(auction.clone(), filler_auth_data, siblings, peaks)
                    .call()
                    .await;

                match claim_result {
                    Ok(_) => {
                        info!("Successfully claimed auction #{}", auction.index);
                    }
                    Err(e) => {
                        error!("Error claiming auction #{}: {:?}", auction.index, e);
                    }
                }
            }
            "Auction claimer task completed"
        });

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(task_result) => {
                    info!("Task completed: {}", task_result);
                }
                Err(e) => {
                    error!("Task failed: {:?}", e);
                }
            }
        }

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
                // Handle state changes (not Created state)
                if auction.state != 0 {
                    // Auction claimed or refunded, check if in queue
                    let mut auctions = pending_auctions.lock().await;

                    // Temp queue for auctions to keep
                    let mut new_queue = BinaryHeap::new();

                    // Remove matching auctions
                    while let Some(Reverse(pending)) = auctions.pop() {
                        if pending.auction.index != auction.index {
                            new_queue.push(Reverse(pending));
                        } else {
                            info!(
                                "Removing auction #{} from queue as its state changed to {}",
                                auction.index, auction.state
                            );
                        }
                    }

                    // Update queue
                    *auctions = new_queue;
                    return Ok(());
                }

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
                        config.btc_fee_sats,
                        config.eth_gas_fee_sats,
                        (provider.get_block_number().await).unwrap_or(0),
                    ) {
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
                }
            }
            Err(e) => {
                error!("Failed to extract auction from log: {:?}", e);
            }
        }
        Ok(())
    }

    /// Check if an auction is still claimable
    pub async fn verify_auction_state(
        provider: DynProvider,
        config: &AuctionClaimerConfig,
        auction: &DutchAuction,
    ) -> Result<bool> {
        // Get auction house contract
        let auction_house_instance =
            BTCDutchAuctionHouseInstance::new(config.auction_house_address, provider.clone());

        // Get auction hash from contract
        let auction_hash = match auction_house_instance
            .auctionHashes(auction.index)
            .call()
            .await
        {
            Ok(hash) => hash,
            Err(e) => {
                error!(
                    "Failed to get auction hash for auction #{}: {:?}",
                    auction.index, e
                );
                return Ok(false); // Can't verify, assume not claimable
            }
        };

        // If hash is zero, auction doesn't exist
        if auction_hash == [0u8; 32] {
            debug!(
                "Auction #{} no longer exists on-chain (hash is zero)",
                auction.index
            );
            return Ok(false);
        }

        // Check if hash matches what we expect
        let auction_encoded = auction.abi_encode();
        let computed_hash = alloy::primitives::keccak256(auction_encoded);

        if auction_hash != computed_hash {
            // Hash mismatch means auction was updated
            debug!(
                "Auction #{} has changed on-chain, hash doesn't match",
                auction.index
            );
            return Ok(false);
        }

        // Double check state is still Created (0)
        if auction.state != 0 {
            debug!(
                "Auction #{} is no longer in Created state, current state: {}",
                auction.index, auction.state
            );
            return Ok(false);
        }

        // Auction is valid and claimable
        Ok(true)
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
            match Self::verify_auction_state(provider.clone(), &config, &pending.auction).await {
                Ok(is_valid) => {
                    if is_valid {
                        auctions_to_claim.push(pending);
                    } else {
                        info!(
                            "Skipping auction #{} - no longer claimable",
                            pending.auction.index
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "Error verifying auction #{}: {:?}",
                        pending.auction.index, e
                    );
                    // Skip this auction
                }
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

    /// Gets Merkle proof for claiming an auction
    pub async fn get_merkle_proof_for_auction(
        &self,
        provider: DynProvider,
        auction: &DutchAuction,
    ) -> Result<(Vec<FixedBytes<32>>, Vec<FixedBytes<32>>)> {
        // Get safe block leaf
        let safe_block_leaf = auction.baseCreateOrderParams.safeBlockLeaf.clone();

        // Validate against light client
        self.validate_block_leaf_with_light_client(provider.clone(), &safe_block_leaf)
            .await?;

        // Get checkpoint MMR
        let checkpoint_mmr = if let Some(mmr) = &self.contract_data_engine {
            mmr.clone()
        } else {
            return Err(eyre!("Contract data engine not initialized"));
        };

        // Get circuit proof
        let circuit_proof = checkpoint_mmr
            .read()
            .await
            .get_circuit_proof(safe_block_leaf.height as usize, None)
            .await
            .map_err(|e| eyre!("Failed to get circuit proof: {:?}", e))?;

        // Convert to FixedBytes format
        let siblings: Vec<FixedBytes<32>> =
            circuit_proof.siblings.iter().map(|s| (*s).into()).collect();

        let peaks: Vec<FixedBytes<32>> = circuit_proof.peaks.iter().map(|p| (*p).into()).collect();

        Ok((siblings, peaks))
    }

    /// Validate block leaf is included in light client
    async fn validate_block_leaf_with_light_client(
        &self,
        provider: DynProvider,
        block_leaf: &BlockLeaf,
    ) -> Result<()> {
        // Get light client address
        let light_client_address = self.get_light_client_address(provider.clone()).await?;

        // Get light client height
        if let Some(light_client_height) = self
            .get_light_client_height(provider, light_client_address)
            .await?
        {
            debug!("Light client height: {}", light_client_height);

            // Validate block leaf height
            if block_leaf.height > light_client_height {
                return Err(eyre!(
                    "Block leaf height {} > light client height {}",
                    block_leaf.height,
                    light_client_height
                ));
            }
        }

        Ok(())
    }

    /// Get light client address
    async fn get_light_client_address(&self, _provider: DynProvider) -> Result<Address> {
        if let Some(address) = self.config.light_client_address {
            debug!("Using light client address: {}", address);

            // Check not zero
            if address == Address::ZERO {
                return Err(eyre!("Light client address is zero address"));
            }

            return Ok(address);
        }

        Err(eyre!("No light client address configured"))
    }

    /// Get light client height
    async fn get_light_client_height(
        &self,
        provider: DynProvider,
        light_client_address: Address,
    ) -> Result<Option<u32>> {
        // Create light client instance
        let light_client =
            sol_bindings::BitcoinLightClientInstance::new(light_client_address, provider.clone());

        match light_client.lightClientHeight().call().await {
            Ok(height) => {
                debug!("Light client height: {}", height);

                return Ok(Some(height));
            }
            Err(e) => {
                error!("Failed to get light client height: {:?}", e);
            }
        }

        Err(eyre!("Failed to get light client height"))
    }
}
