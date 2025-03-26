use bitcoin_light_client_core::leaves::get_genesis_leaf;
use clap::Parser;
use eyre::Result;

use data_engine::engine::ContractDataEngine;
use data_engine_server::DataEngineServer;
use data_engine_server::ServerConfig;
use rift_sdk::DatabaseLocation;
use tokio::task::JoinSet;

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
    let checkpoint_leaves =
        checkpoint_downloader::decompress_checkpoint_file(&config.checkpoint_file).unwrap();
    let mut join_set = JoinSet::new();
    let data_engine_server =
        DataEngineServer::start(config, checkpoint_leaves, &mut join_set).await?;
    join_set.join_all().await;
    Ok(())
}
