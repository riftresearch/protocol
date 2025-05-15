use std::{sync::Arc, time::Duration};

use alloy::providers::Provider;
use bitcoin::Network;
use bitcoincore_rpc_async::Auth;
use clap::Parser;
use rift_sdk::{
    bitcoin_utils::{AsyncBitcoinClient},
    create_websocket_wallet_provider,
    txn_broadcast::TransactionBroadcaster,
    txn_builder::P2WPKHBitcoinWallet,
};
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
                self.evm_private_key
                    .as_bytes()
                    .try_into()
                    .expect("Invalid private key"),
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
        Ok(())
    }
}
