use bitcoin_light_client_core::leaves::get_genesis_leaf;
use clap::Parser;
use eyre::Result;

use data_engine_server::run_server;
use data_engine_server::ServerConfig;

#[tokio::main]
async fn main() -> Result<()> {
    // Set up tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Parse CLI args
    let config = ServerConfig::parse();
    let initial_block_leaf = get_genesis_leaf();
    run_server(config, initial_block_leaf).await
}
