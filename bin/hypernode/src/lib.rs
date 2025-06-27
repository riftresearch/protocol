pub mod fork_watchtower;
pub mod light_client_update_watchtower;
pub mod release_watchtower;
pub mod swap_watchtower;

use alloy::primitives::Address;
pub use alloy::providers::Provider;
use bitcoincore_rpc_async::Auth;
use checkpoint_downloader::decompress_checkpoint_file;
use clap::Parser;
use eyre::Result;
use fork_watchtower::ForkWatchtower;
use light_client_update_watchtower::LightClientUpdateWatchtower;
use release_watchtower::ReleaseWatchtower;
use rift_sdk::proof_generator::{ProofGeneratorType, RiftProofGenerator};
use rift_sdk::txn_broadcast::TransactionBroadcaster;
use rift_sdk::{
    create_websocket_wallet_provider, handle_background_thread_result, DatabaseLocation,
};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use swap_watchtower::SwapWatchtower;
use tokio::task::JoinSet;

use tracing::{info, info_span};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct HypernodeArgs {
    /// Ethereum RPC websocket URL for indexing and proposing proofs onchain
    #[arg(long, env)]
    pub evm_ws_rpc: String,

    /// Bitcoin Core RPC URL with authentication (http(s)://username:password@host:port)
    #[arg(long, env)]
    pub btc_rpc: String,

    /// Ethereum private key for signing hypernode initiated transactions
    #[arg(long, env)]
    pub private_key: String,

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

    /// Log chunk size for Ethereum RPC calls
    #[arg(long, env, default_value = "10000")]
    pub evm_log_chunk_size: u64,

    /// Chunk download size, number of bitcoin rpc requests to execute in a single batch
    #[arg(long, env, default_value = "100")]
    pub btc_batch_rpc_size: usize,

    /// Type of proof generator to use (execute, prove-cpu, prove-cuda, prove-network)
    #[arg(
        long,
        value_parser = ProofGeneratorType::from_str,
        default_value = "prove-network"
    )]
    pub proof_generator: ProofGeneratorType,

    /// Enable automatic light client updates
    #[arg(long, env, default_value = "false")]
    pub enable_auto_light_client_update: bool,

    /// Number of blocks behind Bitcoin tip before triggering a light client update
    #[arg(long, env, default_value = "144")]
    pub auto_light_client_update_block_lag_threshold: u32,

    /// Interval in seconds between checking for light client lag
    #[arg(long, env, default_value = "30")]
    pub auto_light_client_update_check_interval_secs: u64,
}

const BITCOIN_RPC_TIMEOUT: Duration = Duration::from_secs(1);
const BITCOIN_BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(1);

impl HypernodeArgs {
    pub async fn run(&self) -> Result<()> {
        let rift_exchange_address = Address::from_str(&self.rift_exchange_address)?;

        let checkpoint_leaves = decompress_checkpoint_file(&self.checkpoint_file)?;
        info!(
            checkpoint_blocks = checkpoint_leaves.len(),
            "Loaded bitcoin blocks from checkpoint file"
        );

        // [1] create rpc providers for both chains
        let evm_rpc_with_wallet = Arc::new(
            create_websocket_wallet_provider(
                &self.evm_ws_rpc,
                hex::decode(&self.private_key)
                    .map_err(|e| eyre::eyre!(e))?
                    .try_into()
                    .map_err(|_| eyre::eyre!("Invalid private key length"))?,
            )
            .await?,
        );

        let evm_rpc = evm_rpc_with_wallet.clone().erased();

        let btc_rpc = Arc::new(
            rift_sdk::bitcoin_utils::AsyncBitcoinClient::new(
                self.btc_rpc.clone(),
                Auth::None,
                BITCOIN_RPC_TIMEOUT,
            )
            .await?,
        );

        let mut join_set = JoinSet::new();

        let proof_generator_type = self.proof_generator;
        // This takes some actual CPU time to initialize, so we want to do it in a separate non async thread
        // don't spawn this in the join set b/c this is not a long running task
        let proof_generator_handle = tokio::task::spawn_blocking(move || {
            let _span = info_span!("proof_generator_init", generator_type = ?proof_generator_type)
                .entered();
            info!("Starting proof generator initialization");
            Arc::new(RiftProofGenerator::new(proof_generator_type))
        });

        let rift_indexer = {
            info!("Starting contract data engine initialization");
            let engine = rift_indexer::engine::RiftIndexer::start(
                &self.database_location,
                evm_rpc.clone(),
                rift_exchange_address,
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

        let bitcoin_data_engine = {
            info!("Starting bitcoin data engine initialization");
            let engine = bitcoin_data_engine::BitcoinDataEngine::new(
                &self.database_location,
                btc_rpc.clone(),
                self.btc_batch_rpc_size,
                BITCOIN_BLOCK_POLL_INTERVAL,
                &mut join_set,
            )
            .await;
            // Handle the bitcoin data engine background thread crashing before the initial sync completes
            tokio::select! {
                _ = engine.wait_for_initial_sync() => {
                    info!("Bitcoin data engine initialization complete");
                }
                result = join_set.join_next() => {
                    handle_background_thread_result(result)?;
                }
            }
            Arc::new(engine)
        };

        let transaction_broadcaster = Arc::new(TransactionBroadcaster::new(
            evm_rpc_with_wallet.clone(),
            self.evm_ws_rpc.clone(),
            &mut join_set,
        ));

        let proof_generator = proof_generator_handle.await?;

        info!("Starting hypernode watchtowers...");
        SwapWatchtower::run(
            rift_indexer.clone(),
            bitcoin_data_engine.clone(),
            evm_rpc.clone(),
            btc_rpc.clone(),
            rift_exchange_address,
            transaction_broadcaster.clone(),
            self.btc_batch_rpc_size,
            proof_generator.clone(),
            &mut join_set,
        );

        ReleaseWatchtower::run(
            rift_exchange_address,
            transaction_broadcaster.clone(),
            evm_rpc.clone(),
            rift_indexer.clone(),
            &mut join_set,
        )
        .await?;

        ForkWatchtower::run(
            rift_indexer.clone(),
            bitcoin_data_engine.clone(),
            btc_rpc.clone(),
            evm_rpc.clone(),
            rift_exchange_address,
            transaction_broadcaster.clone(),
            self.btc_batch_rpc_size,
            proof_generator.clone(),
            &mut join_set,
        )
        .await?;

        if self.enable_auto_light_client_update {
            LightClientUpdateWatchtower::run(
                self.auto_light_client_update_block_lag_threshold,
                Duration::from_secs(self.auto_light_client_update_check_interval_secs),
                rift_indexer.clone(),
                bitcoin_data_engine.clone(),
                btc_rpc.clone(),
                evm_rpc.clone(),
                rift_exchange_address,
                transaction_broadcaster.clone(),
                self.btc_batch_rpc_size,
                proof_generator.clone(),
                &mut join_set,
            )
            .await?;
        }

        // Wait for one of the background threads to complete or fail. (Ideally never happens, but we want to crash the program if it does)
        handle_background_thread_result(join_set.join_next().await)
    }
}
