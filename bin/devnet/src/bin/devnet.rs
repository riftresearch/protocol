use clap::Parser;
use devnet::evm_devnet::ForkConfig;
use devnet::RiftDevnet;
use eyre::Result;
use log::info;
use rift_sdk::DatabaseLocation;
use tokio::signal;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Address to fund with cbBTC and Ether
    #[arg(short, long)]
    evm_address: Option<String>,

    /// RPC URL to fork from, if unset will not fork
    #[arg(short = 'f', long)]
    fork_url: Option<String>,

    /// Block number to fork from, if unset and fork_url is set, will use the latest block
    #[arg(short = 'b', long)]
    fork_block_number: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("Running devnet...");
    let args = Args::parse();

    let fork_config = if let Some(fork_url) = args.fork_url {
        Some(ForkConfig {
            url: fork_url,
            block_number: args.fork_block_number,
        })
    } else {
        None
    };

    let mut devnet_builder = RiftDevnet::builder()
        .interactive(true)
        .using_bitcoin(true)
        .data_engine_db_location(DatabaseLocation::InMemory);
    if let Some(evm_address) = args.evm_address {
        devnet_builder = devnet_builder.funded_evm_address(evm_address);
    }
    if let Some(fork_config) = fork_config {
        devnet_builder = devnet_builder.fork_config(fork_config);
    }
    let (devnet, _funding_sats) = devnet_builder.build().await?;

    // Wait for Ctrl+C
    signal::ctrl_c().await?;
    drop(devnet);
    Ok(())
}
