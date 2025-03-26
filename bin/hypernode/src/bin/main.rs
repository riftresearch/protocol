use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> eyre::Result<()> {
    // Initialize tracing with env filter (defaults to INFO if RUST_LOG is not set)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = hypernode::HypernodeArgs::parse();
    hypernode::run(args).await
}
