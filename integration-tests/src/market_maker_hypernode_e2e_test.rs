use std::sync::Arc;
use std::time::Duration;

use alloy::{
    primitives::{Address, TxHash, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder, WsConnect},
    sol_types::SolEvent,
};
use bitcoin::Amount;
use data_engine::models::SwapStatus;
use devnet::RiftDevnet;
use eyre::Result;
use hypernode::HypernodeArgs;
use log::{error, info, warn};
use market_maker::MakerConfig;
use rift_sdk::{
    create_websocket_wallet_provider, txn_builder::P2WPKHBitcoinWallet, DatabaseLocation,
    MultichainAccount,
};
use sol_bindings::{AuctionUpdated, BTCDutchAuctionHouse, DutchAuctionParams, MappingWhitelist};
use tokio::time::timeout;

use crate::test_utils::setup_test_tracing;

use bitcoin_data_engine::BitcoinDataEngine;
use bitcoincore_rpc_async::Auth;
use hypernode::{
    fork_watchtower::ForkWatchtower, release_watchtower::ReleaseWatchtower,
    swap_watchtower::SwapWatchtower,
};
use market_maker::{
    auction_claimer::{AuctionClaimer, AuctionClaimerConfig},
    order_filler::{OrderFiller, OrderFillerConfig},
};
use rift_sdk::{
    bitcoin_utils::AsyncBitcoinClient,
    btc_txn_broadcaster::{
        BitcoinTransactionBroadcasterTrait, SimpleBitcoinTransactionBroadcaster,
    },
    fee_provider::{BtcFeeOracle, EthFeeOracle},
    proof_generator::{ProofGeneratorType, RiftProofGenerator},
    txn_broadcast::TransactionBroadcaster,
};
use tokio::task::JoinSet;

#[tokio::test]
async fn test_market_maker_hypernode_end_to_end() {
    setup_test_tracing();
    info!("=== Starting E2E Test ===");

    let result = timeout(Duration::from_secs(300), run_e2e_test()).await;

    match result {
        Ok(Ok(())) => info!("=== E2E Test PASSED ==="),
        Ok(Err(e)) => panic!("E2E test failed: {:?}", e),
        Err(_) => panic!("E2E test timed out after 300 seconds"),
    }
}

async fn run_e2e_test() -> Result<()> {
    let accounts = TestAccounts::new()?;

    let devnet = setup_devnet(&accounts).await?;
    accounts.fund_accounts(&devnet).await?;

    let auction_config = AuctionConfig {
        auction_house_address: *devnet.devnet.ethereum.rift_exchange_contract.address(),
        whitelist_address: Address::from([0x00; 20]),
        data_engine: devnet.devnet.contract_data_engine.clone(),
    };

    let mm_handle = start_market_maker(&accounts, &devnet, &auction_config).await?;

    let hn_handle = start_hypernode(&accounts, &devnet, &auction_config).await?;

    tokio::time::sleep(Duration::from_secs(15)).await;

    if mm_handle.is_finished() {
        return Err(eyre::eyre!(
            "Market Maker exited unexpectedly during startup"
        ));
    }
    if hn_handle.is_finished() {
        return Err(eyre::eyre!("Hypernode exited unexpectedly during startup"));
    }

    devnet
        .devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(20), None)
        .await?;
    let current_block = devnet
        .devnet
        .ethereum
        .funded_provider
        .get_block_number()
        .await?;
    info!(
        "✓ Advanced to block {} - auctions created now will be immediately profitable",
        current_block
    );

    info!("Creating profitable auction NOW - Market Maker WebSocket should be ready");
    let auction_index = create_auction(&accounts, &devnet, &auction_config).await?;
    info!(
        "Auction {} created at block {}",
        auction_index, current_block
    );

    let devnet_arc = Arc::new(devnet);
    let miner_handle = spawn_bitcoin_block_miner(devnet_arc.clone());
    info!("Started background Bitcoin block miner for confirmation tracking");

    monitor_workflow_fn(
        auction_index,
        &auction_config,
        &devnet_arc,
        &mm_handle,
        &hn_handle,
        accounts.market_maker.ethereum_address,
    )
    .await?;

    miner_handle.abort();

    info!(
        "End-to-end workflow completed successfully for auction {}",
        auction_index
    );
    Ok(())
}

struct TestAccounts {
    auction_creator: MultichainAccount,
    market_maker: MultichainAccount,
    hypernode_operator: MultichainAccount,
    taker: MultichainAccount,
}

impl TestAccounts {
    fn new() -> Result<Self> {
        Ok(Self {
            auction_creator: MultichainAccount::new(1),
            market_maker: MultichainAccount::new(2),
            hypernode_operator: MultichainAccount::new(3),
            taker: MultichainAccount::new(4),
        })
    }

    async fn fund_accounts(&self, devnet: &DevnetConfig) -> Result<()> {
        let funding_amount = U256::from(10_000_000_000_000_000_000u128);
        devnet
            .devnet
            .ethereum
            .fund_eth_address(
                self.auction_creator.ethereum_address,
                U256::from(funding_amount),
            )
            .await?;
        devnet
            .devnet
            .ethereum
            .fund_eth_address(
                self.market_maker.ethereum_address,
                U256::from(funding_amount),
            )
            .await?;
        devnet
            .devnet
            .ethereum
            .fund_eth_address(
                self.hypernode_operator.ethereum_address,
                U256::from(funding_amount),
            )
            .await?;
        devnet
            .devnet
            .ethereum
            .fund_eth_address(self.taker.ethereum_address, U256::from(funding_amount))
            .await?;

        let funding_amount_sats = 200_000_000u64;
        devnet
            .devnet
            .bitcoin
            .deal_bitcoin(
                self.auction_creator.bitcoin_wallet.address.clone(),
                Amount::from_sat(funding_amount_sats),
            )
            .await
            .map_err(|e| eyre::eyre!("Failed to fund Market Maker Bitcoin wallet: {}", e))?;
        devnet
            .devnet
            .bitcoin
            .deal_bitcoin(
                self.market_maker.bitcoin_wallet.address.clone(),
                Amount::from_sat(funding_amount_sats),
            )
            .await
            .map_err(|e| eyre::eyre!("Failed to fund Hypernode Operator Bitcoin wallet: {}", e))?;
        devnet
            .devnet
            .bitcoin
            .deal_bitcoin(
                self.hypernode_operator.bitcoin_wallet.address.clone(),
                Amount::from_sat(funding_amount_sats),
            )
            .await
            .map_err(|e| eyre::eyre!("Failed to fund Hypernode Operator Bitcoin wallet: {}", e))?;
        devnet
            .devnet
            .bitcoin
            .deal_bitcoin(
                self.taker.bitcoin_wallet.address.clone(),
                Amount::from_sat(funding_amount_sats),
            )
            .await
            .map_err(|e| eyre::eyre!("Failed to fund Hypernode Operator Bitcoin wallet: {}", e))?;

        Ok(())
    }
}

struct DevnetConfig {
    devnet: RiftDevnet,
    chain_id: u64,
}

async fn setup_devnet(accounts: &TestAccounts) -> Result<DevnetConfig> {
    info!("Setting up DevNet infrastructure...");

    let devnet_builder = RiftDevnet::builder()
        .using_bitcoin(true)
        .using_esplora(true)
        .data_engine_db_location(DatabaseLocation::InMemory)
        .funded_evm_address(accounts.auction_creator.ethereum_address.to_string())
        .funded_evm_address(accounts.market_maker.ethereum_address.to_string())
        .funded_evm_address(accounts.hypernode_operator.ethereum_address.to_string())
        .funded_evm_address(accounts.taker.ethereum_address.to_string());

    let (devnet, _) = devnet_builder.build().await?;
    let chain_id = devnet.ethereum.anvil.chain_id();

    let market_maker_btc_wallet = P2WPKHBitcoinWallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        None,
        bitcoin::Network::Regtest,
        None,
    )?;

    devnet
        .bitcoin
        .deal_bitcoin(
            market_maker_btc_wallet.address.clone(),
            Amount::from_sat(200_000_000),
        )
        .await?;

    info!(
        "Funded Market Maker's actual Bitcoin wallet: {}",
        market_maker_btc_wallet.address
    );
    let mm_provider = create_websocket_wallet_provider(
        devnet.ethereum.anvil.ws_endpoint_url().as_str(),
        accounts.market_maker.secret_bytes,
    )
    .await?;

    let ac_provider = create_websocket_wallet_provider(
        devnet.ethereum.anvil.ws_endpoint_url().as_str(),
        accounts.auction_creator.secret_bytes,
    )
    .await?;

    let token_address = *devnet.ethereum.token_contract.address();
    let auction_house = *devnet.ethereum.rift_exchange_contract.address();

    devnet::TokenizedBTC::new(token_address, mm_provider.erased())
        .approve(auction_house, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;

    devnet::TokenizedBTC::new(token_address, ac_provider.erased())
        .approve(auction_house, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;

    info!("DevNet setup complete");
    Ok(DevnetConfig { devnet, chain_id })
}

struct AuctionConfig {
    auction_house_address: Address,
    whitelist_address: Address,
    data_engine: Arc<data_engine::engine::ContractDataEngine>,
}

async fn start_market_maker(
    accounts: &TestAccounts,
    devnet: &DevnetConfig,
    auction_config: &AuctionConfig,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    info!("Starting Market Maker...");

    let esplora_url = devnet
        .devnet
        .bitcoin
        .electrsd
        .as_ref()
        .and_then(|electrsd| electrsd.esplora_url.clone());

    let config = MakerConfig {
        evm_ws_rpc: devnet.devnet.ethereum.anvil.ws_endpoint_url().to_string(),
        evm_private_key: hex::encode(accounts.market_maker.secret_bytes),
        chain_id: devnet.chain_id,
        btc_rpc: devnet.devnet.bitcoin.rpc_url_with_cookie.clone(),
        btc_rpc_timeout_ms: 10000,
        btc_mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        btc_mnemonic_passphrase: None,
        btc_mnemonic_derivation_path: None,
        btc_network: bitcoin::Network::Regtest,
        auction_house_address: auction_config.auction_house_address.to_string(),
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
        checkpoint_file: devnet.devnet.checkpoint_file_path.clone(),
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

async fn start_hypernode(
    accounts: &TestAccounts,
    devnet: &DevnetConfig,
    auction_config: &AuctionConfig,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    info!("Starting Hypernode...");

    let config = HypernodeArgs {
        evm_ws_rpc: devnet.devnet.ethereum.anvil.ws_endpoint_url().to_string(),
        btc_rpc: devnet.devnet.bitcoin.rpc_url_with_cookie.clone(),
        private_key: hex::encode(accounts.hypernode_operator.secret_bytes),
        checkpoint_file: devnet.devnet.checkpoint_file_path.clone(),
        database_location: DatabaseLocation::InMemory,
        rift_exchange_address: auction_config.auction_house_address.to_string(),
        deploy_block_number: 0,
        log_chunk_size: 10000,
        btc_batch_rpc_size: 100,
        proof_generator: rift_sdk::proof_generator::ProofGeneratorType::Execute,
        enable_auto_light_client_update: false,
        auto_light_client_update_block_lag_threshold: 6,
        auto_light_client_update_check_interval_secs: 30,
    };

    let handle = tokio::spawn(async move {
        config
            .run()
            .await
            .map_err(|e| eyre::eyre!("Hypernode failed: {}", e))
    });

    tokio::time::sleep(Duration::from_secs(3)).await;

    info!("Hypernode started");
    Ok(handle)
}

async fn monitor_workflow_fn(
    auction_index: u64,
    auction_config: &AuctionConfig,
    devnet: &DevnetConfig,
    mm_handle: &tokio::task::JoinHandle<Result<()>>,
    hn_handle: &tokio::task::JoinHandle<Result<()>>,
    market_maker_evm_address: Address,
) -> Result<()> {
    tokio::time::sleep(Duration::from_secs(5)).await;

    monitor_workflow(
        auction_index,
        auction_config,
        devnet,
        mm_handle,
        hn_handle,
        market_maker_evm_address,
    )
    .await
}

async fn create_auction(
    accounts: &TestAccounts,
    devnet: &DevnetConfig,
    auction_config: &AuctionConfig,
) -> Result<u64> {
    let provider = create_websocket_wallet_provider(
        devnet.devnet.ethereum.anvil.ws_endpoint_url().as_str(),
        accounts.auction_creator.secret_bytes,
    )
    .await?;

    let current_timestamp = devnet
        .devnet
        .ethereum
        .funded_provider
        .get_block(
            devnet
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

    let (safe_leaf, _, _) = devnet.devnet.contract_data_engine.get_tip_proof().await?;

    let dutch_params = DutchAuctionParams {
        startBtcOut: U256::from(50_000_000u64),
        endBtcOut: U256::from(40_000_000u64),
        decayBlocks: U256::from(15u64),
        deadline: U256::from(current_timestamp + 3600),
        fillerWhitelistContract: auction_config.whitelist_address,
    };

    let base_params = sol_bindings::BTCDutchAuctionHouse::BaseCreateOrderParams {
        owner: accounts.auction_creator.ethereum_address,
        bitcoinScriptPubKey: accounts
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
        auction_config.auction_house_address,
        provider.erased(),
    );

    let receipt = auction_house
        .startAuction(U256::from(50_000_000u64), dutch_params, base_params)
        .send()
        .await?
        .get_receipt()
        .await?;

    for log in receipt.inner.logs() {
        if log.topics().len() > 0 && log.topics()[0] == AuctionUpdated::SIGNATURE_HASH {
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
    auction_config: &AuctionConfig,
    devnet: &DevnetConfig,
    mm_handle: &tokio::task::JoinHandle<Result<()>>,
    hn_handle: &tokio::task::JoinHandle<Result<()>>,
    market_maker_evm_address: Address,
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

    loop {
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

        match auction_config
            .data_engine
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

                            devnet
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

                            devnet
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
                        _ => {
                            info!("Swap status: {:?}", current_status);
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

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn spawn_bitcoin_block_miner(devnet: Arc<DevnetConfig>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut iteration = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            iteration += 1;
            if let Err(e) = devnet.devnet.bitcoin.mine_blocks(1).await {
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
