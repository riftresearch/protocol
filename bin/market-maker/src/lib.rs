use std::{sync::Arc, time::Duration};

use alloy::providers::Provider;
use bitcoincore_rpc_async::Auth;
use clap::Parser;
use rift_sdk::{
    bitcoin_utils::AsyncBitcoinClient, create_websocket_wallet_provider,
    txn_broadcast::TransactionBroadcaster,
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

    /// Bitcoin Core RPC timeout
    #[arg(long, env, default_value = "10000")]
    pub btc_rpc_timeout_ms: u64,

    /// Ethereum private key for signing transactions
    #[arg(long, env)]
    pub evm_private_key: String,

    /// BIP-39 mnemonic for deriving the Bitcoin wallet used to send payments
    #[arg(long, env)]
    pub btc_mnemonic: String,
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

        Ok(())
    }
}
