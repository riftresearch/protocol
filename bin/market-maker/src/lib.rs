pub mod auction_claimer;
mod main;

use std::{sync::Arc, time::Duration};

use alloy::primitives::Address;
use alloy::providers::Provider;
use auction_claimer::AuctionClaimer;
use bitcoin::Network;
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use bitcoincore_rpc_async::Auth;
use checkpoint_downloader::decompress_checkpoint_file;
use clap::Parser;
use data_engine::engine::ContractDataEngine;
use eyre::Result;
use log::error;
use rift_sdk::{
    bitcoin_utils::{self, AsyncBitcoinClient},
    checkpoint_mmr::CheckpointedBlockTree,
    create_websocket_wallet_provider,
    fee_provider::{BtcFeeOracle, BtcFeeProvider},
    handle_background_thread_result,
    txn_broadcast::TransactionBroadcaster,
    txn_builder::P2WPKHBitcoinWallet,
    DatabaseLocation,
};
use std::str::FromStr;
use tokio::task::JoinSet;
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

    /// Market maker address
    #[arg(long, env)]
    pub market_maker_address: String,

    /// Spread in basis points
    #[arg(long, env, default_value = "50")]
    pub spread_bps: u64,

    /// ETH gas fee in satoshis equivalent
    #[arg(long, env, default_value = "2000")]
    pub eth_gas_fee_sats: u64,

    /// Maximum batch size for claiming auctions
    #[arg(long, env, default_value = "5")]
    pub max_batch_size: usize,

    /// Location of checkpoint file (bitcoin blocks that are committed to at contract deployment)
    #[arg(long, env)]
    pub checkpoint_file: String,

    /// Database location for MMRs one of "memory" or a path to a directory
    #[arg(long, env)]
    pub database_location: DatabaseLocation,

    /// Rift Exchange contract address
    #[arg(long, env)]
    pub rift_exchange_address: String,

    /// Block number of the deployment of the Rift Exchange contract
    #[arg(long, env)]
    pub deploy_block_number: u64,

    /// Log chunk size
    #[arg(long, env, default_value = "10000")]
    pub log_chunk_size: u64,

    /// Chunk download size, number of bitcoin rpc requests to execute in a single batch
    #[arg(long, env, default_value = "100")]
    pub btc_batch_rpc_size: usize,
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

        let btc_wallet = P2WPKHBitcoinWallet::from_mnemonic(
            &self.btc_mnemonic,
            self.btc_mnemonic_passphrase.as_deref(),
            self.btc_network,
            self.btc_mnemonic_derivation_path.as_deref(),
        )?;

        let btc_client = Arc::new(
            AsyncBitcoinClient::new(
                self.btc_rpc.clone(),
                Auth::None,
                Duration::from_millis(self.btc_rpc_timeout_ms),
            )
            .await?,
        );

        let btc_fee_oracle = Arc::new(BtcFeeOracle::new(btc_client.clone()));
        btc_fee_oracle.clone().spawn_updater_in_set(&mut join_set);

        let evm_rpc = wallet_provider.clone().erased();

        let evm_tx_broadcaster = Arc::new(TransactionBroadcaster::new(
            wallet_provider,
            self.evm_ws_rpc.clone(),
            &mut join_set,
        ));

        let rift_exchange_address = Address::from_str(&self.rift_exchange_address)?;

        let checkpoint_leaves = decompress_checkpoint_file(&self.checkpoint_file)?;
        info!(
            checkpoint_blocks = checkpoint_leaves.len(),
            "Loaded bitcoin blocks from checkpoint file"
        );

        /// TODO: Build the market maker logic, spawn the various actors
        // Initialize the auction claimer configuration
        let auction_claimer_config = auction_claimer::AuctionClaimerConfig {
            auction_house_address: Address::from_str(&self.auction_house_address)
                .map_err(|e| eyre::eyre!("Invalid auction house address: {}", e))?,
            market_maker_address: Address::from_str(&self.market_maker_address)
                .map_err(|e| eyre::eyre!("Invalid market maker address: {}", e))?,
            spread_bps: self.spread_bps,
            btc_fee_provider: btc_fee_oracle.clone(),
            eth_gas_fee_sats: self.eth_gas_fee_sats,
            max_batch_size: self.max_batch_size,
            evm_ws_rpc: self.evm_ws_rpc.clone(),
        };

        // Initialize contract data engine if light client address is provided
        let contract_data_engine = {
            info!("Starting contract data engine initialization");
            let engine = data_engine::engine::ContractDataEngine::start(
                &self.database_location,
                evm_rpc.clone(),
                rift_exchange_address,
                self.deploy_block_number,
                self.log_chunk_size,
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

        AuctionClaimer::run(
            evm_rpc.clone(),
            auction_claimer_config,
            contract_data_engine.clone(),
            evm_tx_broadcaster.clone(),
            &mut join_set,
        )
        .await?;

        handle_background_thread_result(join_set.join_next().await)
    }
}
