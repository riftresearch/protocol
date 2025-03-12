use clap::Parser;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> eyre::Result<()> {
    let args = hypernode::HypernodeArgs::parse();
    hypernode::run(args).await
}
