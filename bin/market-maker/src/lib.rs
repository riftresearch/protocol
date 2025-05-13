pub mod auction_claimer;
mod main;

use std::{sync::Arc, time::Duration};

use alloy::primitives::Address;
use alloy::providers::Provider;
use bitcoin::Network;
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use bitcoincore_rpc_async::Auth;
use clap::Parser;
use log::{error, info};
use rift_sdk::{
    bitcoin_utils::{self, AsyncBitcoinClient},
    checkpoint_mmr::CheckpointedBlockTree,
    create_websocket_wallet_provider,
    txn_broadcast::TransactionBroadcaster,
    txn_builder::P2WPKHBitcoinWallet,
    DatabaseLocation,
};
use std::str::FromStr;
use tokio::task::JoinSet;

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

    /// BTC transaction fee in satoshis
    #[arg(long, env, default_value = "1000")]
    pub btc_fee_sats: u64,

    /// ETH gas fee in satoshis equivalent
    #[arg(long, env, default_value = "2000")]
    pub eth_gas_fee_sats: u64,

    /// Maximum batch size for claiming auctions
    #[arg(long, env, default_value = "5")]
    pub max_batch_size: usize,

    /// BitcoinLightClient contract address (optional)
    #[arg(long, env)]
    pub light_client_address: Option<String>,

    /// Database location for MMRs (memory or path to a directory)
    #[arg(long, env, default_value = "memory")]
    pub database_location: String,
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
    pub async fn run(&self) -> eyre::Result<()> {
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

        let evm_rpc = wallet_provider.clone().erased();

        let evm_tx_broadcaster = Arc::new(TransactionBroadcaster::new(
            wallet_provider,
            self.evm_ws_rpc.clone(),
            &mut join_set,
        ));

        /// TODO: Build the market maker logic, spawn the various actors
        // Initialize the auction claimer configuration
        let auction_claimer_config = auction_claimer::AuctionClaimerConfig {
            auction_house_address: Address::from_str(&self.auction_house_address)
                .map_err(|e| eyre::eyre!("Invalid auction house address: {}", e))?,
            market_maker_address: Address::from_str(&self.market_maker_address)
                .map_err(|e| eyre::eyre!("Invalid market maker address: {}", e))?,
            spread_bps: self.spread_bps,
            btc_fee_sats: self.btc_fee_sats,
            eth_gas_fee_sats: self.eth_gas_fee_sats,
            max_batch_size: self.max_batch_size,
            evm_ws_rpc: self.evm_ws_rpc.clone(),
            light_client_address: match &self.light_client_address {
                Some(addr) => Some(
                    Address::from_str(addr)
                        .map_err(|e| eyre::eyre!("Invalid light client address: {}", e))?,
                ),
                None => None,
            },
        };

        // Initialize contract data engine if light client address is provided
        let contract_data_engine = if self.light_client_address.is_some() {
            // Parse database location
            let db_location = if self.database_location.to_lowercase() == "memory" {
                DatabaseLocation::InMemory
            } else {
                DatabaseLocation::Directory(self.database_location.clone())
            };

            // Create a checkpoint tree using the open() method
            info!("Initializing CheckpointedBlockTree for Merkle proofs");
            match CheckpointedBlockTree::<Keccak256Hasher>::open(&db_location).await {
                Ok(tree) => {
                    let checkpoint_tree = Arc::new(tokio::sync::RwLock::new(tree));
                    Some(checkpoint_tree)
                }
                Err(e) => {
                    error!("Failed to initialize CheckpointedBlockTree: {:?}", e);
                    None
                }
            }
        } else {
            None
        };

        // Create the auction claimer
        let auction_claimer = auction_claimer::AuctionClaimer::new(
            self.evm_ws_rpc.clone(),
            self.evm_private_key.clone(),
            auction_claimer_config,
            contract_data_engine,
        );

        info!("Starting auction claimer...");
        join_set.spawn(async move {
            match auction_claimer.run().await {
                Ok(_) => {
                    info!("Auction claimer completed successfully");
                    Ok(())
                }
                Err(e) => {
                    error!("Auction claimer failed: {:?}", e);
                    Err(e)
                }
            }
        });

        // Wait for any of the tasks to complete
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(result) => {
                    if let Err(e) = result {
                        error!("Task failed with error: {:?}", e);
                    } else {
                        info!("Task completed successfully");
                    }
                }
                Err(e) => {
                    error!("Task join failed: {:?}", e);
                }
            }
        }

        Ok(())
    }
}
