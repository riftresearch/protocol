use alloy::eips::eip6110::DEPOSIT_REQUEST_TYPE;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Log as AlloyLog;
use alloy::rpc::types::Log;
use alloy::signers::local::LocalWallet;
use alloy::sol_types::SolEvent;
use alloy_primitives::{FixedBytes, LogData, B256};
use alloy_sol_types::SolValue;
use devnet::RiftDevnet;
use eyre::Result;
use hex;
use log::{debug, error, info, warn};
use market_maker::auction_claimer::{
    calculate_optimal_claim_block, extract_auction_from_log, AuctionClaimer, AuctionClaimerConfig,
    PendingAuction,
};
use rift_sdk::fee_provider::{BtcFeeOracle, BtcFeeProvider, EthFeeOracle, EthFeeProvider};
use rift_sdk::{create_websocket_wallet_provider, DatabaseLocation, MultichainAccount};
use sol_bindings::{
    AuctionUpdated, BTCDutchAuctionHouse, BTCDutchAuctionHouseInstance, DutchAuction,
    DutchAuctionParams, MappingWhitelist, MappingWhitelistInstance, RiftExchangeInstance,
};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{cmp::Reverse, collections::BinaryHeap};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

fn create_test_auction(
    index: u64,
    deposit_amount: u64,
    start_block: u64,
    start_btc_out: u64,
    end_btc_out: u64,
    decay_blocks: u64,
    deadline: u64,
    whitelist_address: Address,
    state: u8,
) -> DutchAuction {
    DutchAuction {
        index: U256::from(index),
        baseCreateOrderParams: sol_bindings::BTCDutchAuctionHouse::BaseCreateOrderParams {
            owner: Address::ZERO,
            bitcoinScriptPubKey: vec![0x00, 0x14].into(),
            salt: FixedBytes::from([0u8; 32]),
            confirmationBlocks: 2,
            safeBlockLeaf: sol_bindings::BTCDutchAuctionHouse::BlockLeaf {
                blockHash: FixedBytes::from([0u8; 32]),
                height: 100,
                cumulativeChainwork: U256::ZERO,
            },
        },
        depositAmount: U256::from(deposit_amount),
        startBlock: U256::from(start_block),
        startTimestamp: U256::from(1000),
        state,
        dutchAuctionParams: DutchAuctionParams {
            startBtcOut: U256::from(start_btc_out),
            endBtcOut: U256::from(end_btc_out),
            decayBlocks: U256::from(decay_blocks),
            deadline: U256::from(deadline),
            fillerWhitelistContract: whitelist_address,
        },
    }
}

fn create_log_from_auction(auction: &DutchAuction) -> Log {
    let event = AuctionUpdated {
        auction: auction.clone(),
    };

    let event_data = event.encode_data();
    let topic = AuctionUpdated::SIGNATURE_HASH;

    let log_data = LogData::new_unchecked(vec![topic.into()], event_data.into());

    Log {
        inner: alloy_primitives::Log {
            address: Address::ZERO,
            data: log_data,
        },
        block_hash: Some(FixedBytes::from([1u8; 32])),
        block_number: Some(100),
        block_timestamp: Some(1200),
        transaction_hash: Some(FixedBytes::from([2u8; 32])),
        transaction_index: Some(0),
        log_index: Some(0),
        removed: false,
    }
}

async fn add_maker_to_whitelist(
    whitelist_contract: &MappingWhitelist::MappingWhitelistInstance<DynProvider>,
    maker_address: Address,
) -> bool {
    debug!(
        "Adding maker {} to whitelist {}",
        maker_address,
        whitelist_contract.address()
    );

    match whitelist_contract
        .addToWhitelist(maker_address)
        .send()
        .await
    {
        Ok(tx) => match tx.get_receipt().await {
            Ok(_) => {
                debug!("Successfully added maker to whitelist");
                true
            }
            Err(e) => {
                error!("Failed to get receipt for whitelist addition: {:?}", e);
                false
            }
        },
        Err(e) => {
            error!("Failed to add maker to whitelist: {:?}", e);
            false
        }
    }
}

#[tokio::test]
async fn test_calculate_optimal_claim_block_comprehensive() {
    let (devnet, _funded_sats) = match RiftDevnet::builder()
        .using_bitcoin(true)
        .using_esplora(true)
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
    {
        Ok(result) => result,
        Err(e) => {
            panic!("Failed to build devnet: {:?}", e);
        }
    };

    let esplora_url = devnet
        .bitcoin
        .electrsd
        .as_ref()
        .expect("Esplora not enabled")
        .esplora_url
        .as_ref()
        .expect("No esplora URL");

    let chain_id = devnet.ethereum.anvil.chain_id();
    let btc_fee_provider = Arc::new(BtcFeeOracle::new(format!("http://{}", esplora_url)));

    let eth_fee_provider = Arc::new(EthFeeOracle::new(devnet.ethereum.funded_provider, chain_id)); // Base chain ID

    let auction_immediate = create_test_auction(
        1,             // index
        100000000,     // deposit_amount (1 BTC in sats)
        100,           // start_block
        10000000,      // start_btc_out (0.1 BTC in sats)
        9000000,       // end_btc_out (0.09 BTC in sats)
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let current_block = 110;
    let spread_bps = 10;

    let optimal_block = calculate_optimal_claim_block(
        &auction_immediate,
        spread_bps,
        btc_fee_provider.clone(),
        eth_fee_provider.clone(),
        current_block,
        None,
    )
    .await;

    assert_eq!(
        optimal_block,
        Some(current_block),
        "Low spread should make auction immediately profitable"
    );

    let auction_future = create_test_auction(
        2,             // index
        100000000,     // deposit_amount (1 BTC in sats)
        100,           // start_block
        50000000,      // start_btc_out (0.5 BTC in sats)
        10000000,      // end_btc_out (0.1 BTC in sats)
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let spread_bps = 150;

    let optimal_block = calculate_optimal_claim_block(
        &auction_future,
        spread_bps,
        btc_fee_provider.clone(),
        eth_fee_provider.clone(),
        current_block,
        None,
    )
    .await;

    assert!(
        optimal_block.is_some(),
        "Should find a profitable block in the future"
    );

    let opt_block = optimal_block.unwrap();
    assert!(
        opt_block >= current_block,
        "Optimal block should be at or after current block (found: {})",
        opt_block
    );

    assert!(
        opt_block <= 100 + 100,
        "Optimal block should be before end of decay period"
    );

    let whitelist_address =
        Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    let auction_whitelist = create_test_auction(
        4,                 // index
        100000000,         // deposit_amount (1 BTC in sats)
        100,               // start_block
        10000000,          // start_btc_out (0.1 BTC in sats)
        9000000,           // end_btc_out (0.09 BTC in sats)
        100,               // decay_blocks
        1000,              // deadline
        whitelist_address, // whitelist
        0,                 // Created state
    );

    let optimal_block = calculate_optimal_claim_block(
        &auction_whitelist,
        10,
        btc_fee_provider.clone(),
        eth_fee_provider.clone(),
        current_block,
        None,
    )
    .await;

    assert_eq!(
        optimal_block,
        Some(current_block),
        "Whitelist should not affect profitability calculation"
    );
}

#[tokio::test]
async fn test_auction_log_extraction() {
    let auction = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let log = create_log_from_auction(&auction);

    let extracted_auction = extract_auction_from_log(&log).unwrap();

    assert_eq!(
        extracted_auction.index, auction.index,
        "Extracted auction index should match original"
    );

    assert_eq!(
        extracted_auction.depositAmount, auction.depositAmount,
        "Extracted deposit amount should match original"
    );

    assert_eq!(
        extracted_auction.dutchAuctionParams.startBtcOut, auction.dutchAuctionParams.startBtcOut,
        "Extracted start BTC out should match original"
    );

    assert_eq!(
        extracted_auction.dutchAuctionParams.endBtcOut, auction.dutchAuctionParams.endBtcOut,
        "Extracted end BTC out should match original"
    );

    assert_eq!(
        extracted_auction.state, auction.state,
        "Extracted state should match original"
    );
}

#[tokio::test]
async fn test_whitelist_verification() {
    info!("Starting test_whitelist_verification");

    let whitelisted_maker = MultichainAccount::new(1);
    let non_whitelisted_maker = MultichainAccount::new(2);
    let auction_owner = MultichainAccount::new(3);

    let (devnet, _funded_sats) = RiftDevnet::builder()
        .using_bitcoin(true)
        .using_esplora(true)
        .funded_evm_address(whitelisted_maker.ethereum_address.to_string())
        .funded_evm_address(non_whitelisted_maker.ethereum_address.to_string())
        .funded_evm_address(auction_owner.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
        .expect("Failed to build devnet");

    let evm_ws_rpc = devnet.ethereum.anvil.ws_endpoint_url().to_string();
    let provider = devnet.ethereum.funded_provider.clone();

    info!("Deploying MappingWhitelist contract...");
    let whitelist_contract = MappingWhitelist::deploy(provider.clone())
        .await
        .expect("Failed to deploy MappingWhitelist");
    let whitelist_address = *whitelist_contract.address();
    info!("Deployed MappingWhitelist at: {}", whitelist_address);

    let whitelist_instance =
        MappingWhitelist::MappingWhitelistInstance::new(whitelist_address, provider.clone());

    info!(
        "Adding whitelisted maker {} to whitelist",
        whitelisted_maker.ethereum_address
    );
    let whitelist_added =
        add_maker_to_whitelist(&whitelist_instance, whitelisted_maker.ethereum_address).await;
    assert!(
        whitelist_added,
        "Failed to add whitelisted maker to whitelist"
    );

    let is_whitelisted = whitelist_instance
        .isWhitelisted(whitelisted_maker.ethereum_address, Bytes::new())
        .call()
        .await
        .expect("Failed to check whitelist status");
    assert!(is_whitelisted, "Whitelisted maker should be whitelisted");

    let is_not_whitelisted = whitelist_instance
        .isWhitelisted(non_whitelisted_maker.ethereum_address, Bytes::new())
        .call()
        .await
        .expect("Failed to check whitelist status");
    assert!(
        !is_not_whitelisted,
        "Non-whitelisted maker should not be whitelisted"
    );

    let auction = create_test_auction(
        1,                 // index
        100000000,         // deposit_amount (1 BTC in sats)
        100,               // start_block
        10000000,          // start_btc_out (0.1 BTC in sats)
        9000000,           // end_btc_out (0.09 BTC in sats)
        100,               // decay_blocks
        1000,              // deadline
        whitelist_address, // whitelist contract address
        0,                 // Created state
    );

    let esplora_url = devnet
        .bitcoin
        .electrsd
        .as_ref()
        .expect("Esplora not enabled")
        .esplora_url
        .as_ref()
        .expect("No esplora URL");
    let chain_id = devnet.ethereum.anvil.chain_id();

    let btc_fee_provider = Arc::new(BtcFeeOracle::new(format!("http://{}", esplora_url)));
    let eth_fee_provider = Arc::new(EthFeeOracle::new(devnet.ethereum.funded_provider, chain_id)); // Base chain ID

    info!("Testing whitelisted maker...");
    let whitelisted_config = AuctionClaimerConfig {
        auction_house_address: Address::ZERO,
        market_maker_address: whitelisted_maker.ethereum_address,
        spread_bps: 10,
        btc_fee_provider: btc_fee_provider.clone(),
        eth_fee_provider: eth_fee_provider.clone(),
        max_batch_size: 10,
        evm_ws_rpc: evm_ws_rpc.clone(),
        btc_tx_size_vbytes: None,
    };

    let pending_auctions = Arc::new(Mutex::new(BinaryHeap::new()));
    let (auction_tx, _) = mpsc::channel(100);

    let log = create_log_from_auction(&auction);

    let result = AuctionClaimer::process_auction_event(
        provider.clone(),
        pending_auctions.clone(),
        whitelisted_config,
        log.clone(),
        auction_tx.clone(),
    )
    .await;

    assert!(
        result.is_ok(),
        "Whitelisted maker should process auction successfully"
    );

    let queue = pending_auctions.lock().await;
    assert_eq!(
        queue.len(),
        1,
        "Whitelisted auction should be added to pending queue"
    );
    drop(queue);

    info!("Testing non-whitelisted maker...");
    let non_whitelisted_config = AuctionClaimerConfig {
        auction_house_address: Address::ZERO,
        market_maker_address: non_whitelisted_maker.ethereum_address,
        spread_bps: 10,
        btc_fee_provider: btc_fee_provider.clone(),
        eth_fee_provider: eth_fee_provider.clone(),
        max_batch_size: 10,
        evm_ws_rpc: evm_ws_rpc.clone(),
        btc_tx_size_vbytes: None,
    };

    let mut queue = pending_auctions.lock().await;
    queue.clear();
    drop(queue);

    let result = AuctionClaimer::process_auction_event(
        provider.clone(),
        pending_auctions.clone(),
        non_whitelisted_config,
        log,
        auction_tx,
    )
    .await;

    assert!(
        result.is_ok(),
        "Processing should not error even for non-whitelisted maker"
    );

    let queue = pending_auctions.lock().await;
    assert_eq!(
        queue.len(),
        0,
        "Non-whitelisted auction should NOT be added to pending queue"
    );

    info!("Whitelist verification test completed successfully");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_auction_claimer_end_to_end() {
    use std::time::Duration;
    use tokio::time::timeout;

    let test_result = timeout(Duration::from_secs(120), async {
        info!("Starting test_auction_claimer_end_to_end");

        let market_maker = MultichainAccount::new(1);
        let filler_account = MultichainAccount::new(2);
        let auction_owner = MultichainAccount::new(3);

        info!("Setting up devnet...");
        let (devnet, _funded_sats) = RiftDevnet::builder()
            .using_bitcoin(true)
            .using_esplora(true)
            .funded_evm_address(market_maker.ethereum_address.to_string())
            .funded_evm_address(filler_account.ethereum_address.to_string())
            .funded_evm_address(auction_owner.ethereum_address.to_string())
            .data_engine_db_location(DatabaseLocation::InMemory)
            .build()
            .await
            .expect("Failed to build devnet");
        info!("Devnet setup complete");

        let evm_ws_rpc = devnet.ethereum.anvil.ws_endpoint_url().to_string();
        info!("WebSocket RPC URL: {}", evm_ws_rpc);

        let private_key_owner = hex::encode(auction_owner.secret_bytes);
        let provider_owner = match create_websocket_wallet_provider(
            &evm_ws_rpc,
            match hex::decode(&private_key_owner) {
                Ok(decoded) => match decoded.try_into() {
                    Ok(key) => key,
                    Err(_) => panic!("Invalid private key length"),
                },
                Err(e) => panic!("Error decoding key: {:?}", e),
            },
        )
        .await
        {
            Ok(provider) => Arc::new(provider),
            Err(e) => panic!("Error creating websocket provider: {:?}", e),
        };

        let private_key_filler = hex::encode(filler_account.secret_bytes);
        let provider_filler = match create_websocket_wallet_provider(
            &evm_ws_rpc,
            match hex::decode(&private_key_filler) {
                Ok(decoded) => match decoded.try_into() {
                    Ok(key) => key,
                    Err(_) => panic!("Invalid private key length"),
                },
                Err(e) => panic!("Error decoding key: {:?}", e),
            },
        )
        .await
        {
            Ok(provider) => Arc::new(provider),
            Err(e) => panic!("Error creating websocket provider: {:?}", e),
        };

        info!("Deploying contracts...");

        let token_address = *devnet.ethereum.token_contract.address();
        info!("Token address from devnet: {}", token_address);

        let token_decimals = devnet
            .ethereum
            .token_contract
            .decimals()
            .call()
            .await
            .unwrap();
        info!("Token decimals: {}", token_decimals);

        let mmr_root = devnet.contract_data_engine.get_mmr_root().await.unwrap();
        let tip_proof = devnet.contract_data_engine.get_tip_proof().await.unwrap();
        let tip_block_leaf = sol_bindings::BTCDutchAuctionHouse::BlockLeaf {
            blockHash: tip_proof.0.block_hash.into(),
            height: tip_proof.0.height,
            cumulativeChainwork: U256::from_be_bytes(tip_proof.0.cumulative_chainwork),
        };

        let whitelist_contract = MappingWhitelist::deploy(provider_owner.clone().erased())
            .await
            .expect("Failed to deploy MappingWhitelist");
        let whitelist_address = *whitelist_contract.address();
        info!("Deployed MappingWhitelist at: {}", whitelist_address);

        let circuit_verification_key_hash = rift_sdk::get_rift_program_hash();
        let verifier_address =
            Address::from_str("0xaeE21CeadF7A03b3034DAE4f190bFE5F861b6ebf").unwrap();
        let fee_router = auction_owner.ethereum_address; // Use auction owner as fee router for testing
        let taker_fee_bips = 10u16;

        let auction_house = BTCDutchAuctionHouse::deploy(
            provider_owner.clone().erased(),
            mmr_root.into(),
            token_address,
            circuit_verification_key_hash.into(),
            verifier_address,
            fee_router,
            taker_fee_bips,
            tip_block_leaf.clone(),
        )
        .await
        .expect("Failed to deploy BTCDutchAuctionHouse");

        let auction_house_address = *auction_house.address();
        info!(
            "Deployed BTCDutchAuctionHouse at: {}",
            auction_house_address
        );

        let current_block = provider_owner.get_block_number().await.unwrap_or(0);
        info!("Current block: {}", current_block);

        let current_timestamp = provider_owner
            .get_block(current_block.into())
            .await
            .unwrap()
            .unwrap()
            .header
            .timestamp;

        let whitelist_dyn = MappingWhitelist::MappingWhitelistInstance::new(
            whitelist_address,
            provider_owner.clone().erased(),
        );

        let whitelist_added =
            add_maker_to_whitelist(&whitelist_dyn, market_maker.ethereum_address).await;
        assert!(whitelist_added, "Failed to add market maker to whitelist");

        let esplora_url = devnet
            .bitcoin
            .electrsd
            .as_ref()
            .expect("Esplora not enabled")
            .esplora_url
            .as_ref()
            .expect("No esplora URL");

        info!("Creating fee providers with esplora URL: {}", esplora_url);
        let btc_fee_provider = Arc::new(BtcFeeOracle::new(format!("http://{}", esplora_url)));
        let chain_id = devnet.ethereum.anvil.chain_id();
        let eth_fee_provider =
            Arc::new(EthFeeOracle::new(devnet.ethereum.funded_provider, chain_id)); // Base chain ID

        let auction_claimer_config = AuctionClaimerConfig {
            auction_house_address,
            market_maker_address: market_maker.ethereum_address,
            spread_bps: 50,
            btc_fee_provider,
            eth_fee_provider,
            max_batch_size: 2,
            evm_ws_rpc: evm_ws_rpc.clone(),
            btc_tx_size_vbytes: None,
        };

        let (auction_tx, mut auction_rx) = mpsc::channel(100);
        let pending_auctions = Arc::new(Mutex::new(BinaryHeap::new()));

        let provider = provider_filler.erased();

        info!("Minting tokens for auction owner...");
        devnet
            .ethereum
            .token_contract
            .mint(auction_owner.ethereum_address, U256::from(1000000000u64))
            .send()
            .await
            .expect("Failed to mint tokens")
            .watch()
            .await
            .expect("Failed to watch mint transaction");

        let token_with_owner = devnet::TokenizedBTC::new(
            *devnet.ethereum.token_contract.address(),
            provider_owner.clone().erased(),
        );
        token_with_owner
            .approve(auction_house_address, U256::MAX)
            .send()
            .await
            .expect("Failed to approve token spending")
            .get_receipt()
            .await
            .expect("Failed to get approval receipt");

        info!("Creating auctions on contract...");

        let auction1_params = DutchAuctionParams {
            startBtcOut: U256::from(10000000u64), // 0.1 BTC
            endBtcOut: U256::from(9000000u64),    // 0.09 BTC
            decayBlocks: U256::from(100u64),
            deadline: U256::from(current_timestamp + 3600), // 1 hour from now
            fillerWhitelistContract: Address::ZERO,
        };

        let base_params1 = sol_bindings::BTCDutchAuctionHouse::BaseCreateOrderParams {
            owner: auction_owner.ethereum_address,
            bitcoinScriptPubKey: vec![0x00, 0x14].into(),
            salt: FixedBytes::from([1u8; 32]),
            confirmationBlocks: 2,
            safeBlockLeaf: tip_block_leaf.clone(),
        };

        let receipt1 = auction_house
            .startAuction(U256::from(100000000u64), auction1_params, base_params1)
            .send()
            .await
            .expect("Failed to create auction 1")
            .get_receipt()
            .await
            .expect("Failed to get auction 1 receipt");
        println!("Auction 1 created in tx: {:?}", receipt1.transaction_hash);

        let auction2_params = DutchAuctionParams {
            startBtcOut: U256::from(50000000u64), // 0.5 BTC
            endBtcOut: U256::from(10000000u64),   // 0.1 BTC
            decayBlocks: U256::from(100u64),
            deadline: U256::from(current_timestamp + 3600), // 1 hour from now
            fillerWhitelistContract: whitelist_address,
        };

        let base_params2 = sol_bindings::BTCDutchAuctionHouse::BaseCreateOrderParams {
            owner: auction_owner.ethereum_address,
            bitcoinScriptPubKey: vec![0x00, 0x14].into(),
            salt: FixedBytes::from([2u8; 32]),
            confirmationBlocks: 2,
            safeBlockLeaf: tip_block_leaf.clone(),
        };

        let receipt2 = auction_house
            .startAuction(U256::from(100000000u64), auction2_params, base_params2)
            .send()
            .await
            .expect("Failed to create auction 2")
            .get_receipt()
            .await
            .expect("Failed to get auction 2 receipt");
        println!("Auction 2 created in tx: {:?}", receipt2.transaction_hash);

        let auction3_params = DutchAuctionParams {
            startBtcOut: U256::from(10000000u64), // 0.1 BTC
            endBtcOut: U256::from(9000000u64),    // 0.09 BTC
            decayBlocks: U256::from(100u64),
            deadline: U256::from(current_timestamp + 3600), // 1 hour from now
            fillerWhitelistContract: Address::ZERO,
        };

        let base_params3 = sol_bindings::BTCDutchAuctionHouse::BaseCreateOrderParams {
            owner: auction_owner.ethereum_address,
            bitcoinScriptPubKey: vec![0x00, 0x14].into(),
            salt: FixedBytes::from([3u8; 32]),
            confirmationBlocks: 2,
            safeBlockLeaf: tip_block_leaf,
        };

        let receipt3 = auction_house
            .startAuction(U256::from(8000000u64), auction3_params, base_params3)
            .send()
            .await
            .expect("Failed to create auction 3")
            .get_receipt()
            .await
            .expect("Failed to get auction 3 receipt");
        println!("Auction 3 created in tx: {:?}", receipt3.transaction_hash);

        info!("Setting up auction event listener...");

        tokio::time::sleep(Duration::from_millis(500)).await;

        let filter = alloy::rpc::types::Filter::new()
            .address(auction_house_address)
            .event(AuctionUpdated::SIGNATURE)
            .from_block(0);

        let logs = provider
            .get_logs(&filter)
            .await
            .expect("Failed to get auction logs");

        println!("Found {} auction logs", logs.len());

        let all_logs = provider
            .get_logs(&alloy::rpc::types::Filter::new())
            .await
            .expect("Failed to get all logs");
        println!("Total logs in blockchain: {}", all_logs.len());

        let mut auction_event_count = 0;
        for log in &all_logs {
            if log.address() == auction_house_address {
                println!(
                    "Found log from auction house at tx: {:?}",
                    log.transaction_hash
                );
                if !log.topics().is_empty() && log.topics()[0] == AuctionUpdated::SIGNATURE_HASH {
                    auction_event_count += 1;
                }
            }
        }
        println!("Total AuctionUpdated events found: {}", auction_event_count);

        println!("Processing {} auction events...", logs.len());
        for (i, log) in logs.iter().enumerate() {
            println!("Processing auction event {}/{}", i + 1, logs.len());

            match extract_auction_from_log(&log) {
                Ok(auction) => {
                    println!(
                        "Extracted auction #{} with state {}",
                        auction.index, auction.state
                    );
                    println!("Auction deposit amount: {}", auction.depositAmount);
                    println!(
                        "Auction start BTC out: {}",
                        auction.dutchAuctionParams.startBtcOut
                    );
                    println!(
                        "Auction end BTC out: {}",
                        auction.dutchAuctionParams.endBtcOut
                    );
                }
                Err(e) => {
                    println!("Failed to extract auction from log: {:?}", e);
                }
            }

            AuctionClaimer::process_auction_event(
                provider.clone(),
                pending_auctions.clone(),
                auction_claimer_config.clone(),
                log.clone(),
                auction_tx.clone(),
            )
            .await
            .expect("Failed to process auction event");
        }

        let queue = pending_auctions.lock().await;
        println!("Pending auctions queue size: {}", queue.len());
        assert!(
            queue.len() > 0,
            "Pending auctions queue should not be empty"
        );

        let contains_auction0 = queue
            .iter()
            .any(|Reverse(pending)| pending.auction.index == U256::from(0));
        assert!(
            contains_auction0,
            "Auction 0 should be in the pending queue"
        );

        let contains_auction2 = queue
            .iter()
            .any(|Reverse(pending)| pending.auction.index == U256::from(2));
        assert!(
            !contains_auction2,
            "Auction 2 should not be in the pending queue (never profitable)"
        );

        drop(queue);

        let next_block = current_block + 10;
        info!("Processing pending auctions at block {}...", next_block);

        AuctionClaimer::process_pending_auctions(
            provider.clone(),
            pending_auctions.clone(),
            next_block,
            auction_claimer_config.max_batch_size,
            auction_tx.clone(),
            auction_claimer_config.clone(),
        )
        .await
        .expect("Failed to process pending auctions");

        let mut auctions_to_claim = Vec::new();

        info!("Waiting for auction to be sent for claiming...");
        let has_auction_to_claim = match timeout(Duration::from_secs(5), auction_rx.recv()).await {
            Ok(Some((auction, claim_block))) => {
                info!(
                    "Received auction {} for claiming at block {}",
                    auction.index, claim_block
                );
                auctions_to_claim.push((auction, claim_block));
                true
            }
            Ok(None) => {
                error!("Channel closed unexpectedly");
                false
            }
            Err(_) => {
                error!("Timeout waiting for auction to be sent for claiming");
                false
            }
        };

        assert!(
            has_auction_to_claim,
            "Should have at least one auction to claim"
        );

        let contains_auction0 = auctions_to_claim
            .iter()
            .any(|(auction, _)| auction.index == U256::from(0));
        assert!(
            contains_auction0,
            "Auction 0 should be selected for claiming"
        );

        info!("Test completed successfully without state change verification");

        info!("test_auction_claimer_end_to_end completed successfully");
    })
    .await;

    match test_result {
        Ok(_) => {}
        Err(_) => panic!("Test timed out after 120 seconds"),
    }
}
