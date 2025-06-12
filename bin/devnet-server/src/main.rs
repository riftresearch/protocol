use clap::Parser;
use devnet::evm_devnet::ForkConfig;
use devnet::RiftDevnet;
use eyre::Result;
use log::info;
use rift_sdk::{handle_background_thread_result, DatabaseLocation};
use tokio::signal;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Address to fund with cbBTC and Ether
    #[arg(short, long)]
    fund_address: Vec<String>,

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
