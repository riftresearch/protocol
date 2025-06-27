use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use clap::{Parser, Subcommand};
use devnet::evm_devnet::ForkConfig;
use devnet::{RiftDevnet, RiftDevnetCache};
use eyre::Result;
use log::info;
use rift_sdk::handle_background_thread_result;
use std::{collections::HashMap, str::FromStr, sync::LazyLock};
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run devnet server (interactive mode)
    Server {
        /// Address to fund with cbBTC and Ether
        #[arg(short, long)]
        fund_address: Vec<String>,

        /// RPC URL to fork from, if unset will not fork
        #[arg(short = 'f', long)]
        fork_url: String,

        /// Block number to fork from, if unset and fork_url is set, will use the latest block
        #[arg(short = 'b', long)]
        fork_block_number: Option<u64>,
    },
    /// Create and save a cached devnet for faster subsequent runs
    Cache,
}

static BUNDLER_CHAIN_MAP: LazyLock<HashMap<u64, Address>> = LazyLock::new(|| {
    HashMap::from([
        (
            1,
            Address::from_str("0x6566194141eefa99Af43Bb5Aa71460Ca2Dc90245").unwrap(),
        ),
        (
            8453,
            Address::from_str("0x6BFd8137e702540E7A42B74178A4a49Ba43920C4").unwrap(),
        ),
    ])
});

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server {
            fund_address,
            fork_url,
            fork_block_number,
        } => run_server(fund_address, fork_url, fork_block_number).await,
        Commands::Cache => run_cache().await,
    }
}

async fn run_server(
    fund_address: Vec<String>,
    fork_url: String,
    fork_block_number: Option<u64>,
) -> Result<()> {
    let server_start = tokio::time::Instant::now();
    info!("[Devnet Server] Starting devnet server...");

    let chain_id_start = tokio::time::Instant::now();
    let chain_id = ProviderBuilder::new()
        .on_http(fork_url.parse()?)
        .get_chain_id()
        .await
        .expect("Failed to get chain id");
    info!("[Devnet Server] Retrieved chain ID {} in {:?}", chain_id, chain_id_start.elapsed());

    if !BUNDLER_CHAIN_MAP.contains_key(&chain_id) {
        eyre::bail!("Chain ID {} is not supported", chain_id);
    }

    let fork_config = Some(ForkConfig {
        url: fork_url,
        block_number: fork_block_number,
        bundler3_address: *BUNDLER_CHAIN_MAP.get(&chain_id).unwrap(),
    });

    let mut devnet_builder = RiftDevnet::builder().interactive(true).using_esplora(true);

    for address in fund_address {
        devnet_builder = devnet_builder.funded_evm_address(address);
    }

    if let Some(fork_config) = fork_config {
        devnet_builder = devnet_builder.fork_config(fork_config);
    }
    info!("[Devnet Server] Building devnet...");
    let build_start = tokio::time::Instant::now();
    let (mut devnet, _funding_sats) = devnet_builder.build().await?;
    info!("[Devnet Server] Devnet built in {:?}", build_start.elapsed());
    info!("[Devnet Server] Total startup time: {:?}", server_start.elapsed());

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("[Devnet Server] Ctrl+C received, shutting down...");
        }
        _ = async {
            if let Some(res) = devnet.join_set.join_next().await {
                handle_background_thread_result(Some(res)).expect("A background service failed");
            }
        } => {
            info!("[Devnet Server] A background service failed");
        }
    }

    drop(devnet);
    Ok(())
}

async fn run_cache() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init()
        .ok();
    let cache_start = tokio::time::Instant::now();
    info!("[Devnet Cache] Creating cached devnet...");

    // Create cache instance and save the devnet
    let cache = RiftDevnetCache::new();

    // clear the cache directory then save
    tokio::fs::remove_dir_all(&cache.cache_dir).await.ok();

    // Build devnet using for_cached configuration
    let build_start = tokio::time::Instant::now();
    let (devnet, _funding_sats) = RiftDevnet::builder_for_cached().build().await?;
    info!("[Devnet Cache] Devnet built in {:?}", build_start.elapsed());

    info!("[Devnet Cache] Devnet created successfully, saving to cache...");
    let save_start = tokio::time::Instant::now();
    cache.save_devnet(devnet).await?;
    info!("[Devnet Cache] Cache saved in {:?}", save_start.elapsed());

    info!("[Devnet Cache] Devnet cached successfully! Total time: {:?}", cache_start.elapsed());

    Ok(())
}
