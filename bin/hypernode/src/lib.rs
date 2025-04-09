pub mod release_watchtower;
pub mod swap_watchtower;
pub mod txn_broadcast;

use alloy::primitives::Address;
pub use alloy::providers::Provider;
use bitcoin::base58::error;
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::{Auth, RpcApi};
use checkpoint_downloader::decompress_checkpoint_file;
use clap::Parser;
use eyre::Result;
use release_watchtower::ReleaseWatchtower;
use rift_sdk::proof_generator::{ProofGeneratorType, RiftProofGenerator};
use rift_sdk::{create_websocket_provider, create_websocket_wallet_provider, DatabaseLocation};
use serde_json;
use std::fs::File;
use std::io::{BufReader, Read};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use swap_watchtower::SwapWatchtower;
use tokio::runtime::Runtime;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, info_span, Instrument, Level};
use tracing_subscriber::{self, EnvFilter};
use txn_broadcast::TransactionBroadcaster;

fn handle_background_thread_result<T>(
    result: Option<Result<Result<T, eyre::Report>, tokio::task::JoinError>>,
) -> eyre::Result<()> {
    match result {
        Some(Ok(thread_result)) => match thread_result {
            Ok(_) => Err(eyre::eyre!("Background thread completed unexpectedly")),
            Err(e) => Err(eyre::eyre!("Background thread panicked: {}", e)),
        },
        Some(Err(e)) => Err(eyre::eyre!("Join set failed: {}", e)),
        None => Err(eyre::eyre!("Join set panicked with no result")),
    }
}

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
}

const BITCOIN_RPC_TIMEOUT: Duration = Duration::from_secs(1);
const BITCOIN_BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(1);

pub async fn run(args: HypernodeArgs) -> Result<()> {
    let rift_exchange_address = Address::from_str(&args.rift_exchange_address)?;

    let checkpoint_leaves = decompress_checkpoint_file(&args.checkpoint_file)?;
    info!(
        checkpoint_blocks = checkpoint_leaves.len(),
        "Loaded bitcoin blocks from checkpoint file"
    );

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

    let mut join_set = JoinSet::new();

    // This takes some actual CPU time to initialize, so we want to do it in a separate non async thread
    // don't spawn this in the join set b/c this is not a long running task
    let proof_generator_handle = tokio::task::spawn_blocking(move || {
        let _span =
            info_span!("proof_generator_init", generator_type = ?args.proof_generator).entered();
        info!("Starting proof generator initialization");
        Arc::new(RiftProofGenerator::new(args.proof_generator))
    });

    let contract_data_engine = {
        info!("Starting contract data engine initialization");
        let engine = data_engine::engine::ContractDataEngine::start(
            &args.database_location,
            evm_rpc.clone(),
            rift_exchange_address,
            args.deploy_block_number,
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
            &args.database_location,
            btc_rpc.clone(),
            args.btc_batch_rpc_size,
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
        evm_rpc.clone(),
        args.evm_ws_rpc.clone(),
        &mut join_set,
    ));

    let proof_generator = proof_generator_handle.await?;

    info!("Starting hypernode watchtowers...");
    SwapWatchtower::run(
        contract_data_engine.clone(),
        bitcoin_data_engine.clone(),
        evm_rpc.clone(),
        btc_rpc.clone(),
        rift_exchange_address,
        transaction_broadcaster.clone(),
        args.btc_batch_rpc_size,
        proof_generator,
        &mut join_set,
    );

    ReleaseWatchtower::run(
        rift_exchange_address,
        transaction_broadcaster.clone(),
        evm_rpc.clone(),
        contract_data_engine.clone(),
        &mut join_set,
    )
    .await?;

    // Wait for one of the background threads to complete or fail. (Ideally never happens, but we want to crash the program if it does)
    handle_background_thread_result(join_set.join_next().await)
}
