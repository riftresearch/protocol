use hypernode::HypernodeArgs;
use rift_sdk::{proof_generator::ProofGeneratorType, DatabaseLocation};
use tokio::task::JoinHandle;

use super::fixtures::TestFixture;

/// Configuration for spawning a hypernode
pub struct HypernodeConfig {
    pub proof_generator: ProofGeneratorType,
    pub enable_auto_light_client_update: bool,
    pub auto_light_client_update_block_lag_threshold: u32,
    pub auto_light_client_update_check_interval_secs: u64,
    pub btc_batch_rpc_size: usize,
    pub evm_log_chunk_size: u64,
    pub private_key: Option<String>,
}

impl Default for HypernodeConfig {
    fn default() -> Self {
        Self {
            proof_generator: ProofGeneratorType::Execute,
            enable_auto_light_client_update: false,
            auto_light_client_update_block_lag_threshold: 6,
            auto_light_client_update_check_interval_secs: 30,
            btc_batch_rpc_size: 100,
            evm_log_chunk_size: 10000,
            private_key: None,
        }
    }
}

/// Spawn a hypernode with the given configuration
pub async fn spawn_hypernode(fixture: &TestFixture, config: HypernodeConfig) -> JoinHandle<()> {
    let rpc_url_with_cookie = fixture.devnet.bitcoin.rpc_url_with_cookie.clone();
    let ws_endpoint = fixture.devnet.ethereum.anvil.ws_endpoint_url().to_string();
    let rift_exchange_address = fixture
        .devnet
        .ethereum
        .rift_exchange_contract
        .address()
        .to_string();
    let checkpoint_file = fixture.checkpoint_file_path();
    let private_key = config.private_key.unwrap_or_else(|| {
        hex::encode(fixture.accounts.hypernode_operator.secret_bytes)
    });

    tokio::spawn(async move {
        let hypernode_args = HypernodeArgs {
            evm_ws_rpc: ws_endpoint,
            btc_rpc: rpc_url_with_cookie,
            private_key,
            checkpoint_file,
            database_location: DatabaseLocation::InMemory,
            rift_exchange_address,
            deploy_block_number: 0,
            btc_batch_rpc_size: config.btc_batch_rpc_size,
            evm_log_chunk_size: config.evm_log_chunk_size,
            proof_generator: config.proof_generator,
            enable_auto_light_client_update: config.enable_auto_light_client_update,
            auto_light_client_update_block_lag_threshold: config
                .auto_light_client_update_block_lag_threshold,
            auto_light_client_update_check_interval_secs: config
                .auto_light_client_update_check_interval_secs,
            confirmations: 1,
        };

        hypernode_args.run().await.expect("Hypernode crashed");
    })
}

/// Spawn a hypernode with default configuration
pub async fn spawn_default_hypernode(fixture: &TestFixture) -> JoinHandle<()> {
    spawn_hypernode(fixture, HypernodeConfig::default()).await
}

/// Helper to spawn a hypernode and wait for it to be ready
pub async fn spawn_and_wait_for_hypernode(fixture: &TestFixture) -> JoinHandle<()> {
    let handle = spawn_default_hypernode(fixture).await;

    handle
}
