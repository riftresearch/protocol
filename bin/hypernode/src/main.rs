use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::{Auth, RpcApi};
use checkpoint_downloader::decompress_checkpoint_file;
use clap::Parser;
use rift_sdk::{create_websocket_provider, DatabaseLocation};
use serde_json;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct HypernodeArgs {
    /// Ethereum RPC websocket URL for indexing and proposing proofs onchain
    #[arg(short, long, env)]
    pub evm_ws_rpc: String,

    /// Bitcoin Core RPC URL with authentication (http(s)://username:password@host:port)
    #[arg(short, long, env)]
    pub btc_rpc: String,

    /// Ethereum private key for signing hypernode initiated transactions
    #[arg(short, long, env)]
    pub private_key: String,

    /// Location of checkpoint file (bitcoin blocks that are committed to at deployment)
    #[arg(short, long, env)]
    pub checkpoint_file: String,

    /// Database location for MMRs
    #[arg(short, long, env)]
    pub database_location: DatabaseLocation,

    /// Rift Exchange contract address
    #[arg(short, long, env)]
    pub rift_exchange_address: String,

    /// Block number of the deployment of the Rift Exchange contract
    #[arg(short, long, env)]
    pub deploy_block_number: u64,

    /// Chunk download size, number of bitcoin rpc requests to execute in a single batch
    #[arg(short, long, env, default_value = "100")]
    pub btc_batch_rpc_size: usize,

    /// Enable mock proof generation
    #[arg(short, long, env, default_value = "false")]
    pub mock_proof: bool,
}

const BITCOIN_RPC_TIMEOUT: Duration = Duration::from_secs(1);
const BITCOIN_BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = HypernodeArgs::parse();

    // [1] create provider
    let evm_rpc = Arc::new(create_websocket_provider(&args.evm_ws_rpc).await?);

    let btc_rpc = Arc::new(
        rift_sdk::bitcoin_utils::AsyncBitcoinClient::new(
            args.btc_rpc,
            Auth::None,
            BITCOIN_RPC_TIMEOUT,
        )
        .await?,
    );

    let checkpoint_leaves = decompress_checkpoint_file(&args.checkpoint_file)?;
    println!(
        "Loaded {} bitcoin blocks from checkpoint file",
        checkpoint_leaves.len()
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
    let contract_data_engine_duration = start_time.elapsed();
    println!(
        "Contract data engine initialized in {:?}",
        contract_data_engine_duration
    );

    /*
        database_location: DatabaseLocation,
        bitcoin_rpc: Arc<AsyncBitcoinClient>,
        download_chunk_size: usize,
        block_search_interval: Duration,
    */

    let bitcoin_data_engine = bitcoin_data_engine::BitcoinDataEngine::new(
        &args.database_location,
        btc_rpc,
        args.btc_batch_rpc_size,
        BITCOIN_BLOCK_POLL_INTERVAL,
    )
    .await;

    println!("Starting hypernode service...");

    Ok(())
}
