//! Example of subscribing and listening for all contract events by `WebSocket` subscription.

use clap::{command, Parser};
use data_engine::{run_data_engine, setup_database};
use eyre::Result;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Websocket URL of the EVM network to subscribe to events on  
    #[arg(long)]
    evm_rpc_websocket_url: String,

    /// Rift Exchange contract address
    #[arg(long)]
    rift_exchange_address: String,

    /// Use in-memory SQLite database instead of file
    #[arg(long)]
    in_memory: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = Args::parse();
    let pool = setup_database(args.in_memory).await?;
    run_data_engine(
        &args.evm_rpc_websocket_url,
        &args.rift_exchange_address,
        &pool,
    )
    .await
}
