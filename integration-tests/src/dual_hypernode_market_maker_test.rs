use std::sync::Arc;
use std::time::Duration;

use alloy::{
    primitives::{Address, U256},
    providers::{ext::AnvilApi, Provider},
    sol_types::SolEvent,
};
use bitcoin::Amount;
use eyre::Result;
use log::{info, warn};
use market_maker::MakerConfig;
use rift_indexer::models::SwapStatus;
use rift_sdk::{
    txn_builder::P2WPKHBitcoinWallet, DatabaseLocation,
};
use sol_bindings::{AuctionUpdated, BTCDutchAuctionHouse, DutchAuctionParams};
use tokio::time::timeout;

use crate::test_helpers::{
    fixtures::{TestConfig, TestFixture},
    hypernode_helpers::{spawn_hypernode, HypernodeConfig},
};

#[tokio::test]
async fn test_dual_hypernode_market_maker_order_filling() {
    info!("=== Starting Dual Hypernode Market Maker Test ===");

    let result = timeout(Duration::from_secs(300), run_dual_hypernode_test()).await;

    match result {
        Ok(Ok(())) => info!("=== Dual Hypernode Test PASSED ==="),
        Ok(Err(e)) => panic!("Dual hypernode test failed: {:?}", e),
        Err(_) => panic!("Dual hypernode test timed out after 300 seconds"),
    }
}

async fn run_dual_hypernode_test() -> Result<()> {
    // Setup test fixture with an additional account for the second hypernode
    let config = TestConfig {
        auto_mine_ethereum: false,
        num_additional_makers: 1,
    };
    let fixture = TestFixture::with_config(config).await;
    
    // Fund the additional account with max ETH for the second hypernode
    fixture
        .devnet
        .ethereum
        .fund_eth_address(
            fixture.accounts.additional_makers[0].ethereum_address,
            U256::MAX,
        )
        .await?;
    
    // Fund additional accounts
    fund_test_accounts(&fixture).await?;
    
    // Start market maker
    let mm_handle = start_market_maker(&fixture).await?;
    
    // Start first hypernode with default config (uses hypernode_operator account)
    info!("Starting first hypernode with hypernode_operator account...");
    let hypernode1_handle = spawn_hypernode(&fixture, HypernodeConfig::default()).await;
    
    // Start second hypernode with different account and config
    info!("Starting second hypernode with additional_maker account...");
    let mut hypernode2_config = HypernodeConfig::default();
    hypernode2_config.btc_batch_rpc_size = 50; // Different batch size to make them distinguishable
    hypernode2_config.private_key = Some(hex::encode(fixture.accounts.additional_makers[0].secret_bytes));
    let hypernode2_handle = spawn_hypernode(&fixture, hypernode2_config).await;

    // Wait for all services to initialize
    info!("Waiting 20 seconds for all services to initialize...");
    tokio::time::sleep(Duration::from_secs(20)).await;

    // Initial health check
    if mm_handle.is_finished() {
        return Err(eyre::eyre!("Market Maker exited unexpectedly during startup"));
    }
    if hypernode1_handle.is_finished() {
        return Err(eyre::eyre!("Hypernode 1 exited unexpectedly during startup"));
    }
    if hypernode2_handle.is_finished() {
        return Err(eyre::eyre!("Hypernode 2 exited unexpectedly during startup"));
    }
    info!("✓ All services started successfully");

    // Mine blocks to make auctions profitable
    fixture
        .devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(20), None)
        .await?;
    
    // Wait for Market Maker WebSocket to stabilize
    info!("Waiting 5 seconds for Market Maker WebSocket to stabilize...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Create auction
    let auction_index = create_auction(&fixture).await?;
    info!("Created auction with index: {}", auction_index);

    // Mine blocks to enable auction claiming
    fixture
        .devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(5), None)
        .await?;

    // Start Bitcoin block miner
    let miner_handle = spawn_bitcoin_block_miner(fixture.devnet.clone());
    
    // Monitor workflow with health checks for both hypernodes
    monitor_dual_hypernode_workflow(
        auction_index,
        &fixture,
        &mm_handle,
        &hypernode1_handle,
        &hypernode2_handle,
    )
    .await?;

    miner_handle.abort();

    // Final health check
    if hypernode1_handle.is_finished() {
        return Err(eyre::eyre!("Hypernode 1 crashed during test"));
    }
    if hypernode2_handle.is_finished() {
        return Err(eyre::eyre!("Hypernode 2 crashed during test"));
    }
    
    info!("✓ Both hypernodes remained online throughout the test");
    info!("✓ Order successfully reached ChallengePeriod state");
    
    Ok(())
}

async fn fund_test_accounts(fixture: &TestFixture) -> Result<()> {
    let funding_amount = U256::from(10_000_000_000_000_000_000u128);
    let funding_amount_sats = 200_000_000u64;
    
    // Fund maker
    fixture
        .devnet
        .ethereum
        .fund_eth_address(
            fixture.accounts.maker.ethereum_address,
            funding_amount,
        )
        .await?;
    
    fixture
        .devnet
        .bitcoin
        .deal_bitcoin(
            fixture.accounts.maker.bitcoin_wallet.address.clone(),
            Amount::from_sat(funding_amount_sats),
        )
        .await
        .map_err(|e| eyre::eyre!("Failed to fund Maker Bitcoin wallet: {}", e))?;
    
    // Fund taker
    fixture
        .devnet
        .ethereum
        .fund_eth_address(
            fixture.accounts.taker.ethereum_address,
            funding_amount,
        )
        .await?;
    
    fixture
        .devnet
        .bitcoin
        .deal_bitcoin(
            fixture.accounts.taker.bitcoin_wallet.address.clone(),
            Amount::from_sat(funding_amount_sats),
        )
        .await
        .map_err(|e| eyre::eyre!("Failed to fund Taker Bitcoin wallet: {}", e))?;
    
    // Fund market maker's Bitcoin wallet
    let market_maker_btc_wallet = P2WPKHBitcoinWallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        None,
        bitcoin::Network::Regtest,
        None,
    )?;
    
    fixture
        .devnet
        .bitcoin
        .deal_bitcoin(
            market_maker_btc_wallet.address.clone(),
            Amount::from_sat(funding_amount_sats),
        )
        .await?;
    
    // Approve token spending
    let token_address = *fixture.devnet.ethereum.token_contract.address();
    let auction_house = *fixture.devnet.ethereum.rift_exchange_contract.address();
    
    let mm_provider = fixture.create_provider_for(&fixture.accounts.maker).await;
    devnet::TokenizedBTC::new(token_address, Box::new(mm_provider))
        .approve(auction_house, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;
    
    let taker_provider = fixture.create_provider_for(&fixture.accounts.taker).await;
    devnet::TokenizedBTC::new(token_address, Box::new(taker_provider))
        .approve(auction_house, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;
    
    Ok(())
}

async fn start_market_maker(
    fixture: &TestFixture,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    info!("Starting Market Maker...");

    let esplora_url = fixture
        .devnet
        .bitcoin
        .electrsd
        .as_ref()
        .and_then(|electrsd| electrsd.esplora_url.clone());

    let config = MakerConfig {
        evm_ws_rpc: fixture.devnet.ethereum.anvil.ws_endpoint_url().to_string(),
        evm_private_key: hex::encode(fixture.accounts.maker.secret_bytes),
        chain_id: fixture.devnet.ethereum.anvil.chain_id(),
        btc_rpc: fixture.devnet.bitcoin.rpc_url_with_cookie.clone(),
        btc_rpc_timeout_ms: 10000,
        btc_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        btc_mnemonic_passphrase: None,
        btc_mnemonic_derivation_path: None,
        btc_network: bitcoin::Network::Regtest,
        auction_house_address: fixture.devnet.ethereum.rift_exchange_contract.address().to_string(),
        spread_bps: 0,
        max_batch_size: 5,
        btc_tx_size_vbytes: None,
        esplora_api_url: esplora_url.clone().map(|url| {
            if url.starts_with("http://") || url.starts_with("https://") {
                url
            } else {
                format!("http://{}", url)
            }
        }).unwrap_or_else(|| {
            "http://localhost:3002".to_string()
        }),
        checkpoint_file: fixture.checkpoint_file_path(),
        database_location: DatabaseLocation::InMemory,
        deploy_block_number: 0,
        evm_log_chunk_size: 10000,
        btc_batch_rpc_size: 100,
        order_delay_seconds: 5,
        order_max_batch_size: 5,
        order_required_confirmations: 2,
        order_confirmation_timeout: 300,
        coinbase_api_key: None,
        coinbase_api_secret: None,
        market_maker_btc_address: None,
        cbbtc_contract_address: None,
        minimum_redeem_threshold_sats: 1000000,
        evm_confirmations: 1,
    };

    let handle = tokio::spawn(async move {
        info!("MARKET MAKER: Starting run() method...");
        let result = config.run().await;
        result.map_err(|e| eyre::eyre!("Market Maker failed: {}", e))
    });

    tokio::time::sleep(Duration::from_secs(5)).await;

    if handle.is_finished() {
        return Err(eyre::eyre!("Market Maker exited during startup phase"));
    }

    info!("Market Maker startup phase complete");
    Ok(handle)
}

async fn create_auction(fixture: &TestFixture) -> Result<u64> {
    let provider = fixture.create_provider_for(&fixture.accounts.maker).await;

    let current_timestamp = fixture
        .devnet
        .ethereum
        .funded_provider
        .get_block(
            fixture
                .devnet
                .ethereum
                .funded_provider
                .get_block_number()
                .await?
                .into(),
        )
        .await?
        .unwrap()
        .header
        .timestamp;

    let (safe_leaf, _, _) = fixture.devnet.rift_indexer.get_tip_proof().await?;

    let dutch_params = DutchAuctionParams {
        startBtcOut: U256::from(50_000_000u64),
        endBtcOut: U256::from(40_000_000u64),
        decayBlocks: U256::from(15u64),
        deadline: U256::from(current_timestamp + 3600),
        fillerWhitelistContract: Address::from([0x00; 20]),
    };

    let base_params = sol_bindings::BTCDutchAuctionHouse::BaseCreateOrderParams {
        owner: fixture.accounts.maker.ethereum_address,
        bitcoinScriptPubKey: fixture
            .accounts
            .taker
            .bitcoin_wallet
            .get_p2wpkh_script()
            .to_bytes()
            .into(),
        salt: [0x06u8; 32].into(),
        confirmationBlocks: 2,
        safeBlockLeaf: sol_bindings::BTCDutchAuctionHouse::BlockLeaf {
            blockHash: safe_leaf.block_hash.into(),
            height: safe_leaf.height,
            cumulativeChainwork: U256::from_be_bytes(safe_leaf.cumulative_chainwork),
        },
    };

    let auction_house = BTCDutchAuctionHouse::BTCDutchAuctionHouseInstance::new(
        *fixture.devnet.ethereum.rift_exchange_contract.address(),
        Box::new(provider),
    );

    let receipt = auction_house
        .startAuction(U256::from(50_000_000u64), dutch_params, base_params)
        .send()
        .await?
        .get_receipt()
        .await?;

    for log in receipt.inner.logs() {
        if !log.topics().is_empty() && log.topics()[0] == AuctionUpdated::SIGNATURE_HASH {
            if let Ok(event) = AuctionUpdated::decode_log(&log.inner) {
                let auction_index = event.data.auction.index.to::<u64>();
                return Ok(auction_index);
            }
        }
    }

    Err(eyre::eyre!("Failed to extract auction index from receipt"))
}

async fn monitor_dual_hypernode_workflow(
    auction_index: u64,
    fixture: &TestFixture,
    mm_handle: &tokio::task::JoinHandle<Result<()>>,
    hypernode1_handle: &tokio::task::JoinHandle<()>,
    hypernode2_handle: &tokio::task::JoinHandle<()>,
) -> Result<()> {
    info!("Monitoring workflow for auction {} with dual hypernodes...", auction_index);

    let mut last_status: Option<SwapStatus> = None;
    let timeout_duration = Duration::from_secs(180);
    let start_time = std::time::Instant::now();
    let mut health_check_counter = 0u32;

    loop {
        health_check_counter += 1;
        
        // Perform health checks every iteration
        if mm_handle.is_finished() {
            return Err(eyre::eyre!("Market Maker exited unexpectedly"));
        }
        if hypernode1_handle.is_finished() {
            return Err(eyre::eyre!("Hypernode 1 exited unexpectedly"));
        }
        if hypernode2_handle.is_finished() {
            return Err(eyre::eyre!("Hypernode 2 exited unexpectedly"));
        }
        
        // Log health status periodically
        if health_check_counter % 20 == 0 {
            info!("Health check #{}: All services running", health_check_counter / 20);
        }

        if start_time.elapsed() > timeout_duration {
            let status_msg = if last_status.is_some() {
                format!("Last status was: {:?}", last_status.unwrap())
            } else {
                "No swap found".to_string()
            };
            return Err(eyre::eyre!("Timeout waiting for ChallengePeriod: {}", status_msg));
        }

        match fixture
            .devnet
            .rift_indexer
            .get_otc_swap_by_order_index(auction_index)
            .await
        {
            Ok(Some(swap)) => {
                let current_status = swap.swap_status();

                if last_status.as_ref() != Some(&current_status) {
                    info!("Swap status changed to: {:?}", current_status);
                    
                    match &current_status {
                        SwapStatus::PaymentPending => {
                            info!("Market Maker claimed auction - waiting for Bitcoin payment");
                            
                            // Mine Bitcoin blocks for payment
                            fixture
                                .devnet
                                .bitcoin
                                .mine_blocks(3)
                                .await
                                .map_err(|e| eyre::eyre!("Failed to mine Bitcoin blocks: {}", e))?;

                            tokio::time::sleep(Duration::from_secs(10)).await;
                        }
                        SwapStatus::ChallengePeriod => {
                            info!("✓ Order reached ChallengePeriod state!");
                            info!("✓ Both hypernodes are still online");
                            
                            // Verify once more that both hypernodes are still running
                            if !hypernode1_handle.is_finished() && !hypernode2_handle.is_finished() {
                                return Ok(());
                            } else {
                                return Err(eyre::eyre!("One or both hypernodes crashed after reaching ChallengePeriod"));
                            }
                        }
                        SwapStatus::Completed => {
                            return Err(eyre::eyre!("Swap completed before we could verify ChallengePeriod state"));
                        }
                        SwapStatus::Refunded => {
                            return Err(eyre::eyre!("Swap was refunded - workflow failed"));
                        }
                    }
                    last_status = Some(current_status);
                }
            }
            Ok(None) => {
                if start_time.elapsed() > Duration::from_secs(30) {
                    warn!("Auction {} not claimed after 30 seconds", auction_index);
                }
            }
            Err(e) => {
                warn!("Data engine query error: {}", e);
            }
        }

        // Mine EVM block periodically
        if health_check_counter % 10 == 0 {
            if let Err(e) = fixture
                .devnet
                .ethereum
                .funded_provider
                .anvil_mine(Some(1), None)
                .await
            {
                warn!("Failed to mine EVM block: {}", e);
            }
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn spawn_bitcoin_block_miner(devnet: Arc<devnet::RiftDevnet>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut iteration = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            iteration += 1;
            if let Err(e) = devnet.bitcoin.mine_blocks(1).await {
                warn!("Failed to mine Bitcoin block: {}", e);
            } else {
                info!("Mined Bitcoin block #{}", iteration);
            }
        }
    })
}