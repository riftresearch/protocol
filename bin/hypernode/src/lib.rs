pub mod swap_watchtower;
pub mod txn_broadcast;

use alloy::providers::Provider;
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::{Auth, RpcApi};
use checkpoint_downloader::decompress_checkpoint_file;
use clap::Parser;
use eyre::Result;
use rift_sdk::{create_websocket_provider, create_websocket_wallet_provider, DatabaseLocation};
use serde_json;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tracing::{info, Level};
use tracing_subscriber::{self, EnvFilter};

#[derive(Parser, Debug)]
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

    /// Chunk download size, number of bitcoin rpc requests to execute in a single batch
    #[arg(long, env, default_value = "100")]
    pub btc_batch_rpc_size: usize,

    /// Enable mock proof generation
    #[arg(long, env, default_value = "false")]
    pub mock_proof: bool,
}

const BITCOIN_RPC_TIMEOUT: Duration = Duration::from_secs(1);
const BITCOIN_BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(1);

pub async fn run(args: HypernodeArgs) -> Result<()> {
    // Initialize tracing with env filter (defaults to INFO if RUST_LOG is not set)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // [1] create rpc providers for both chains
    let evm_rpc = Arc::new(
        create_websocket_wallet_provider(
            &args.evm_ws_rpc,
            hex::decode(&args.private_key)
                .map_err(|e| eyre::eyre!(e))?
                .try_into()
                .map_err(|_| eyre::eyre!("Invalid private key length"))?,
        )
        .await?,
    );

    let btc_rpc = Arc::new(
        rift_sdk::bitcoin_utils::AsyncBitcoinClient::new(
            args.btc_rpc,
            Auth::None,
            BITCOIN_RPC_TIMEOUT,
        )
        .await?,
    );

    let checkpoint_leaves = decompress_checkpoint_file(&args.checkpoint_file)?;
    info!(
        checkpoint_blocks = checkpoint_leaves.len(),
        "Loaded bitcoin blocks from checkpoint file"
    );

    let start_time = Instant::now();
    let contract_data_engine = data_engine::engine::DataEngine::start(
        &args.database_location,
        evm_rpc,
        args.rift_exchange_address,
        args.deploy_block_number,
        checkpoint_leaves,
    )
    .await?;
    contract_data_engine.wait_for_initial_sync().await?;

    let contract_data_engine_duration = start_time.elapsed();
    info!(
        duration_ms = contract_data_engine_duration.as_millis(),
        "Contract data engine initialized"
    );

    let bitcoin_data_engine = bitcoin_data_engine::BitcoinDataEngine::new(
        &args.database_location,
        btc_rpc,
        args.btc_batch_rpc_size,
        BITCOIN_BLOCK_POLL_INTERVAL,
    )
    .await;
    bitcoin_data_engine.wait_for_initial_sync().await?;
    // TODO: create Txn Broadcaster
    // TODO: Create proof builder

    info!("Starting hypernode service...");

    Ok(())
}
