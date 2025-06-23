use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use clap::Parser;
use devnet::evm_devnet::ForkConfig;
use devnet::RiftDevnet;
use eyre::Result;
use log::info;
use rift_sdk::{handle_background_thread_result, DatabaseLocation};
use std::{collections::HashMap, str::FromStr, sync::LazyLock};
use tokio::signal;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Address to fund with cbBTC and Ether
    #[arg(short, long)]
    fund_address: Vec<String>,

    /// RPC URL to fork from, if unset will not fork
    #[arg(short = 'f', long)]
    fork_url: String,

    /// Block number to fork from, if unset and fork_url is set, will use the latest block
    #[arg(short = 'b', long)]
    fork_block_number: Option<u64>,
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
    info!("Running devnet...");
    let args = Args::parse();
    let chain_id = ProviderBuilder::new()
        .on_http(args.fork_url.parse()?)
        .get_chain_id()
        .await
        .expect("Failed to get chain id");

    if !BUNDLER_CHAIN_MAP.contains_key(&chain_id) {
        eyre::bail!("Chain ID {} is not supported", chain_id);
    }

    let fork_config = Some(ForkConfig {
        url: args.fork_url,
        block_number: args.fork_block_number,
        bundler3_address: *BUNDLER_CHAIN_MAP.get(&chain_id).unwrap(),
    });

    let mut devnet_builder = RiftDevnet::builder()
        .interactive(true)
        .using_bitcoin(true)
        .using_esplora(true)
        .data_engine_db_location(DatabaseLocation::InMemory);

    for address in args.fund_address {
        devnet_builder = devnet_builder.funded_evm_address(address);
    }

    if let Some(fork_config) = fork_config {
        devnet_builder = devnet_builder.fork_config(fork_config);
    }
    let (mut devnet, _funding_sats) = devnet_builder.build().await?;

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Ctrl+C received, shutting down...");
        }
        _ = async {
            if let Some(res) = devnet.join_set.join_next().await {
                handle_background_thread_result(Some(res)).expect("A background service failed");
            }
        } => {
            info!("A background service failed");
        }
    }

    drop(devnet);
    Ok(())
}
