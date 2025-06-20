pub mod auction_claimer;
pub mod db;
pub mod order_filler;
pub mod tokenized_btc_redeemer;

use std::{sync::Arc, time::Duration};

use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::providers::WalletProvider;
use auction_claimer::AuctionClaimer;
use bitcoin::Network;
use bitcoin_data_engine::BitcoinDataEngine;
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use bitcoincore_rpc_async::Auth;
use checkpoint_downloader::decompress_checkpoint_file;
use clap::Parser;
use data_engine::engine::ContractDataEngine;
use esplora_client::AsyncClient as EsploraClient;
use eyre::Result;
use log::error;
use order_filler::{OrderFiller, OrderFillerConfig};
use rift_sdk::btc_txn_broadcaster::BitcoinTransactionBroadcasterTrait;
use rift_sdk::btc_txn_broadcaster::SimpleBitcoinTransactionBroadcaster;
use rift_sdk::fee_provider::EthFeeOracle;
use rift_sdk::{
    bitcoin_utils::AsyncBitcoinClient,
    checkpoint_mmr::CheckpointedBlockTree,
    create_websocket_wallet_provider,
    fee_provider::{BtcFeeOracle, BtcFeeProvider},
    handle_background_thread_result,
    txn_broadcast::TransactionBroadcaster,
    txn_builder::P2WPKHBitcoinWallet,
    DatabaseLocation,
};
use std::str::FromStr;
use tokenized_btc_redeemer::{
    create_redeemer_actor, trigger_redemption_on_order_settled, TokenizedBTCRedeemerConfig,
};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_rusqlite::Connection;
use tracing::info;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct MakerConfig {
    /// Ethereum RPC websocket URL for indexing and broadcasting transactions
    #[arg(long, env)]
    pub evm_ws_rpc: String,

    /// Bitcoin Core RPC URL with authentication (http(s)://username:password@host:port)
    #[arg(long, env)]
    pub btc_rpc: String,

    /// Bitcoin Core RPC timeout (ms)
    #[arg(long, env, default_value = "10000")]
    pub btc_rpc_timeout_ms: u64,

    /// Ethereum private key for signing transactions
    #[arg(long, env)]
    pub evm_private_key: String,

    /// BIP-39 mnemonic phrase for deriving the Bitcoin wallet used to send payments
    #[arg(long, env)]
    pub btc_mnemonic: String,

    /// BIP-39 mnemonic passphrase for the Bitcoin wallet
    #[arg(long, env)]
    pub btc_mnemonic_passphrase: Option<String>,

    /// BIP-84 derivation path for the Bitcoin wallet (if not the first derivation path)
    #[arg(long, env)]
    pub btc_mnemonic_derivation_path: Option<String>,

    /// BTC Network (bitcoin, testnet, testnet4, signet, regtest)
    #[arg(long, env, default_value = "bitcoin", value_parser = parse_network)]
    pub btc_network: Network,

    /// BTCDutchAuctionHouse contract address
    #[arg(long, env)]
    pub auction_house_address: String,

    /// Spread in basis points
    #[arg(long, env, default_value = "50")]
    pub spread_bps: u64,

    /// Maximum batch size for claiming auctions
    #[arg(long, env, default_value = "5")]
    pub max_batch_size: usize,

    /// BTC transaction size in virtual bytes (optional, defaults to standard tx size)
    #[arg(long, env)]
    pub btc_tx_size_vbytes: Option<u64>,

    /// Esplora (blockstream/electrs) API URL for fetching BTC fee rates
    #[arg(long, env)]
    pub esplora_api_url: String,

    /// Location of checkpoint file (bitcoin blocks that are committed to at contract deployment)
    #[arg(long, env)]
    pub checkpoint_file: String,

    /// Database location for MMRs one of "memory" or a path to a directory
    #[arg(long, env)]
    pub database_location: DatabaseLocation,

    /// Block number of the deployment of the Rift Exchange contract
    #[arg(long, env)]
    pub deploy_block_number: u64,

    /// Log chunk size
    #[arg(long, env, default_value = "10000")]
    pub evm_log_chunk_size: u64,

    /// Chunk download size, number of bitcoin rpc requests to execute in a single batch
    #[arg(long, env, default_value = "100")]
    pub btc_batch_rpc_size: usize,

    /// Chain ID for the EVM network
    #[arg(long, env, default_value = "1")]
    pub chain_id: u64,

    /// OrderFiller: Minimum delay in seconds before processing orders
    #[arg(long, env, default_value = "30")]
    pub order_delay_seconds: u64,

    /// OrderFiller: Maximum batch size for processing orders
    #[arg(long, env, default_value = "10")]
    pub order_max_batch_size: usize,

    /// OrderFiller: Required Bitcoin confirmations for order completion
    #[arg(long, env, default_value = "6")]
    pub order_required_confirmations: u32,

    /// OrderFiller: Timeout in seconds for waiting for confirmations
    #[arg(long, env, default_value = "86400")]
    pub order_confirmation_timeout: u64,

    /// Coinbase API Key for cbBTC redemption
    #[arg(long, env)]
    pub coinbase_api_key: Option<String>,

    /// Coinbase API Secret for cbBTC redemption
    #[arg(long, env)]
    pub coinbase_api_secret: Option<String>,

    /// Address for receiving redeemed BTC
    #[arg(long, env)]
    pub market_maker_btc_address: Option<String>,

    /// cbBTC ERC20 contract address
    #[arg(long, env)]
    pub cbbtc_contract_address: Option<String>,

    /// Minimum amount of cbBTC in sats to trigger redemption
    #[arg(long, env, default_value = "1000000")]
    pub minimum_redeem_threshold_sats: u64,
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s.to_lowercase().as_str() {
        "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(format!(
            "Invalid network: {}. Must be one of: bitcoin, testnet, testnet4, signet, regtest",
            s
        )),
    }
}

impl MakerConfig {
    pub async fn run(&self) -> Result<()> {
        let mut join_set = JoinSet::new();
        let wallet_provider = Arc::new(
            create_websocket_wallet_provider(
                &self.evm_ws_rpc,
                hex::decode(&self.evm_private_key)
                    .map_err(|e| eyre::eyre!(e))?
                    .try_into()
                    .map_err(|_| eyre::eyre!("Invalid private key length"))?,
            )
            .await?,
        );

        let market_maker_address = wallet_provider.default_signer_address();

        let btc_wallet = P2WPKHBitcoinWallet::from_mnemonic(
            &self.btc_mnemonic,
            self.btc_mnemonic_passphrase.as_deref(),
            self.btc_network,
            self.btc_mnemonic_derivation_path.as_deref(),
        )?;

        let btc_fee_oracle = Arc::new(BtcFeeOracle::new(self.esplora_api_url.clone()));
        btc_fee_oracle.clone().spawn_updater_in_set(&mut join_set);

        let evm_rpc = wallet_provider.clone().erased();

        let eth_fee_oracle = Arc::new(EthFeeOracle::new(evm_rpc.clone(), self.chain_id));
        eth_fee_oracle.clone().spawn_updater_in_set(&mut join_set);
        info!(
            "ETH Fee Provider (EthFeeOracle) initialized and updater spawned for chain_id: {}",
            self.chain_id
        );

        let evm_tx_broadcaster = Arc::new(TransactionBroadcaster::new(
            wallet_provider,
            self.evm_ws_rpc.clone(),
            &mut join_set,
        ));

        let checkpoint_leaves = decompress_checkpoint_file(&self.checkpoint_file)?;
        info!(
            checkpoint_blocks = checkpoint_leaves.len(),
            "Loaded bitcoin blocks from checkpoint file"
        );

        let auction_house_address = Address::from_str(&self.auction_house_address)
            .map_err(|e| eyre::eyre!("Invalid auction house address: {}", e))?;

        // Initialize the auction claimer configuration
        let auction_claimer_config = auction_claimer::AuctionClaimerConfig {
            auction_house_address,
            market_maker_address,
            spread_bps: self.spread_bps,
            btc_fee_provider: btc_fee_oracle.clone(),
            eth_fee_provider: eth_fee_oracle.clone(),
            max_batch_size: self.max_batch_size,
            evm_ws_rpc: self.evm_ws_rpc.clone(),
            btc_tx_size_vbytes: self.btc_tx_size_vbytes,
        };

        // Initialize contract data engine if light client address is provided
        let contract_data_engine = {
            info!("Starting contract data engine initialization");
            let engine = data_engine::engine::ContractDataEngine::start(
                &self.database_location,
                evm_rpc.clone(),
                auction_house_address,
                self.deploy_block_number,
                self.evm_log_chunk_size,
                checkpoint_leaves,
                &mut join_set,
            )
            .await?;
            // Handle the contract data engine background thread crashing before the initial sync completes
            tokio::select! {
                _ = engine.wait_for_initial_sync() => {
                    info!("Contract data engine initialization complete");
                }
                result = join_set.join_next() => {
                    handle_background_thread_result(result)?;
                }
            }
            Arc::new(engine)
        };

        let bitcoin_rpc = Arc::new(
            AsyncBitcoinClient::new(
                self.btc_rpc.clone(),
                Auth::UserPass("user".to_string(), "password".to_string()),
                Duration::from_millis(self.btc_rpc_timeout_ms),
            )
            .await?,
        );
        info!("Bitcoin RPC client initialized: {}", self.btc_rpc);

        let bitcoin_data_engine = Arc::new(
            BitcoinDataEngine::new(
                &self.database_location,
                bitcoin_rpc.clone(),
                self.btc_batch_rpc_size,
                Duration::from_secs(10),
                &mut join_set,
            )
            .await,
        );
        info!(
            "Bitcoin data engine initialized for network: {:?}",
            self.btc_network
        );

        let esplora_client = Arc::new(
            esplora_client::Builder::new(&self.esplora_api_url)
                .build_async()
                .map_err(|e| eyre::eyre!("Failed to create Esplora client: {}", e))?,
        );
        info!("Esplora client initialized: {}", self.esplora_api_url);

        let bitcoin_broadcaster = Arc::new(
            SimpleBitcoinTransactionBroadcaster::new(
                bitcoin_rpc.clone(),
                esplora_client,
                btc_wallet,
                &mut join_set,
            )
            .await,
        );
        info!("Bitcoin transaction broadcaster initialized");

        let order_filler_db = Arc::new(
            Connection::open_in_memory()
                .await
                .map_err(|e| eyre::eyre!("Failed to create OrderFiller database: {}", e))?,
        );
        info!("OrderFiller database initialized");

        let redeemer_trigger_sender = match (
            &self.coinbase_api_key,
            &self.coinbase_api_secret,
            &self.market_maker_btc_address,
            &self.cbbtc_contract_address,
        ) {
            (Some(api_key), Some(api_secret), Some(btc_address), Some(cbbtc_address)) => {
                let cbbtc_contract_address = Address::from_str(cbbtc_address)
                    .map_err(|e| eyre::eyre!("Invalid cbBTC contract address: {}", e))?;

                let redeemer_config = TokenizedBTCRedeemerConfig {
                    coinbase_api_key: api_key.clone(),
                    coinbase_api_secret: api_secret.clone(),
                    market_maker_btc_address: btc_address.clone(),
                    cbbtc_contract_address,
                    market_maker_address,
                    minimum_redeem_threshold_sats: self.minimum_redeem_threshold_sats,
                };

                let redeemer_actor = create_redeemer_actor(redeemer_config, evm_rpc.clone())?;

                let trigger_sender = redeemer_actor.get_trigger_sender();

                join_set.spawn(async move {
                    match redeemer_actor.run().await {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            error!("Tokenized Bitcoin Redeemer crashed: {:?}", e);
                            Err(e)
                        }
                    }
                });

                info!("Tokenized Bitcoin Redeemer started successfully");
                Some(trigger_sender)
            }
            _ => {
                info!("Tokenized Bitcoin Redeemer disabled (missing configuration)");
                None
            }
        };

        let order_filler_config = OrderFillerConfig {
            market_maker_address,
            rift_exchange_address: auction_house_address,
            delay_seconds: self.order_delay_seconds,
            max_batch_size: self.order_max_batch_size,
            database_location: self.database_location.clone(),
            required_confirmations: self.order_required_confirmations,
            confirmation_timeout: self.order_confirmation_timeout,
        };

        OrderFiller::run(
            evm_rpc.clone(),
            order_filler_config,
            bitcoin_broadcaster,
            bitcoin_rpc,
            bitcoin_data_engine,
            order_filler_db,
            redeemer_trigger_sender,
            &mut join_set,
        )
        .await?;
        info!("OrderFiller started successfully");

        AuctionClaimer::run(
            evm_rpc.clone(),
            auction_claimer_config,
            contract_data_engine.clone(),
            evm_tx_broadcaster.clone(),
            &mut join_set,
        )?;
        info!("AuctionClaimer started successfully");

        handle_background_thread_result(join_set.join_next().await)
    }
}
