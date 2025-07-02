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
    fixtures::TestFixture,
    hypernode_helpers::{spawn_hypernode, HypernodeConfig},
};

#[tokio::test]
async fn test_market_maker_hypernode_end_to_end() {
    info!("=== Starting E2E Test ===");

    let result = timeout(Duration::from_secs(300), run_e2e_test()).await;

    match result {
        Ok(Ok(())) => info!("=== E2E Test PASSED ==="),
        Ok(Err(e)) => panic!("E2E test failed: {:?}", e),
        Err(_) => panic!("E2E test timed out after 300 seconds"),
    }
}

async fn run_e2e_test() -> Result<()> {
    // Setup test fixture with standard configuration
    let fixture = TestFixture::new().await;
    
    // Fund additional accounts needed for the test
    fund_additional_accounts(&fixture).await?;
    
    // Start market maker
    let mm_handle = start_market_maker(&fixture).await?;
    
    // Start hypernode
    let hn_handle = spawn_hypernode(&fixture, HypernodeConfig::default()).await;

    // Wait for services to fully initialize and establish WebSocket connections
    info!("Waiting 20 seconds for services to initialize...");
    tokio::time::sleep(Duration::from_secs(20)).await;

    if mm_handle.is_finished() {
        return Err(eyre::eyre!(
            "Market Maker exited unexpectedly during startup"
        ));
    }
    if hn_handle.is_finished() {
        return Err(eyre::eyre!("Hypernode exited unexpectedly during startup"));
    }

    // Mine blocks to make auctions immediately profitable
    fixture
        .devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(20), None)
        .await?;
    let current_block = fixture
        .devnet
        .ethereum
        .funded_provider
        .get_block_number()
        .await?;
    info!(
        "✓ Advanced to block {} - auctions created now will be immediately profitable",
        current_block
    );

    // Wait for Market Maker's WebSocket subscription to be fully established
    info!("Waiting 5 seconds for Market Maker WebSocket subscription to stabilize...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    info!("Creating profitable auction NOW - Market Maker WebSocket should be ready");
    let auction_index = create_auction(&fixture).await?;
    info!(
        "Auction {} created at block {}",
        auction_index, current_block
    );

    // Mine multiple EVM blocks to ensure auction can be claimed and orders can be processed
    info!("Mining EVM blocks to enable auction claiming and order processing...");
    fixture
        .devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(5), None)
        .await?;

    let miner_handle = spawn_bitcoin_block_miner(fixture.devnet.clone());
    info!("Started background Bitcoin block miner for confirmation tracking");

    monitor_workflow(
        auction_index,
        &fixture,
        &mm_handle,
        &hn_handle,
        fixture.accounts.maker.ethereum_address,
    )
    .await?;

    miner_handle.abort();

    info!(
        "End-to-end workflow completed successfully for auction {}",
        auction_index
    );
    Ok(())
}

async fn fund_additional_accounts(fixture: &TestFixture) -> Result<()> {
    let funding_amount = U256::from(10_000_000_000_000_000_000u128);
    let funding_amount_sats = 200_000_000u64;
    
    // Fund maker with ETH
    fixture
        .devnet
        .ethereum
        .fund_eth_address(
            fixture.accounts.maker.ethereum_address,
            funding_amount,
        )
        .await?;
    
    // Fund taker with ETH
    fixture
        .devnet
        .ethereum
        .fund_eth_address(
            fixture.accounts.taker.ethereum_address,
            funding_amount,
        )
        .await?;
    
    // Fund maker with BTC
    fixture
        .devnet
        .bitcoin
        .deal_bitcoin(
            fixture.accounts.maker.bitcoin_wallet.address.clone(),
            Amount::from_sat(funding_amount_sats),
        )
        .await
        .map_err(|e| eyre::eyre!("Failed to fund Maker Bitcoin wallet: {}", e))?;
    
    // Fund taker with BTC
    fixture
        .devnet
        .bitcoin
        .deal_bitcoin(
            fixture.accounts.taker.bitcoin_wallet.address.clone(),
            Amount::from_sat(funding_amount_sats),
        )
        .await
        .map_err(|e| eyre::eyre!("Failed to fund Taker Bitcoin wallet: {}", e))?;
    
    // Fund the actual market maker wallet with BTC
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
    
    info!(
        "Funded Market Maker's actual Bitcoin wallet: {}",
        market_maker_btc_wallet.address
    );
    
    // Approve token spending for market maker and taker
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

    info!("Market Maker startup phase complete (process still running)");
    Ok(handle)
}

async fn create_auction(
    fixture: &TestFixture,
) -> Result<u64> {
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
                info!("Auction created with index: {}", auction_index);
                return Ok(auction_index);
            }
        }
    }

    Err(eyre::eyre!("Failed to extract auction index from receipt"))
}

async fn monitor_workflow(
    auction_index: u64,
    fixture: &TestFixture,
    mm_handle: &tokio::task::JoinHandle<Result<()>>,
    hn_handle: &tokio::task::JoinHandle<()>,
    _market_maker_evm_address: Address,
) -> Result<()> {
    info!(
        "Monitoring end-to-end workflow for auction {}...",
        auction_index
    );

    let mut last_status: Option<SwapStatus> = None;
    let timeout_duration = Duration::from_secs(180);
    let start_time = std::time::Instant::now();
    let mut no_claim_warning_shown = false;
    let mut payment_sent_time: Option<std::time::Instant> = None;
    let mut loop_iteration = 0u32;

    loop {
        loop_iteration += 1;
        if mm_handle.is_finished() {
            return Err(eyre::eyre!(
                "Market Maker process exited unexpectedly during workflow monitoring"
            ));
        }
        if hn_handle.is_finished() {
            return Err(eyre::eyre!(
                "Hypernode process exited unexpectedly during workflow monitoring"
            ));
        }

        if start_time.elapsed() > timeout_duration {
            let status_msg = if last_status.is_some() {
                format!("Last status was: {:?}", last_status.unwrap())
            } else {
                "No swap found".to_string()
            };

            return Err(eyre::eyre!(
                "Timeout Error: {} for auction {} with status {}",
                timeout_duration.as_secs(),
                auction_index,
                status_msg
            ));
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
                    match &current_status {
                        SwapStatus::PaymentPending => {
                            info!("Market Maker claimed auction - waiting for Bitcoin payment");
                            payment_sent_time = Some(std::time::Instant::now());

                            fixture
                                .devnet
                                .bitcoin
                                .mine_blocks(3)
                                .await
                                .map_err(|e| eyre::eyre!("Failed to mine Bitcoin blocks: {}", e))?;

                            tokio::time::sleep(Duration::from_secs(20)).await;
                        }
                        SwapStatus::ChallengePeriod => {
                            info!("Bitcoin payment detected - in challenge period");
                            // Now warp ahead on the eth chain to the timestamp that unlocks the swap
                            let swap_unlock_timestamp = swap
                                .payments
                                .first()
                                .unwrap()
                                .payment
                                .challengeExpiryTimestamp
                                + 1;

                            fixture
                                .devnet
                                .ethereum
                                .funded_provider
                                .anvil_set_time(swap_unlock_timestamp)
                                .await
                                .unwrap();
                        }
                        SwapStatus::Completed => {
                            info!("Swap completed - end-to-end workflow successful!");
                            return Ok(());
                        }
                        SwapStatus::Refunded => {
                            return Err(eyre::eyre!("Swap was refunded - workflow failed"));
                        }
                    }
                    last_status = Some(current_status);
                }
            }
            Ok(None) => {
                if !no_claim_warning_shown && start_time.elapsed() > Duration::from_secs(30) {
                    warn!(
                        "Auction {} not claimed after 30 seconds. Market Maker may not be detecting auction events.",
                        auction_index
                    );

                    if mm_handle.is_finished() {
                        return Err(eyre::eyre!(
                            "Market Maker process exited unexpectedly after 30 seconds"
                        ));
                    }
                    no_claim_warning_shown = true;
                }

                if let Some(payment_time) = payment_sent_time {
                    if payment_time.elapsed() > Duration::from_secs(60) {
                        return Err(eyre::eyre!(
                            "Payment Error: {}",
                            payment_time.elapsed().as_secs()
                        ));
                    }
                }
            }
            Err(e) => {
                warn!("Data engine query error: {}", e);
            }
        }

        // Mine an EVM block every 10 iterations (5 seconds) to ensure order processing
        if loop_iteration % 10 == 0 {
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
                warn!("Failed to mine background Bitcoin block: {}", e);
            } else {
                info!(
                    "Mined background Bitcoin block #{} for confirmation tracking",
                    iteration
                );
            }
        }
    })
}