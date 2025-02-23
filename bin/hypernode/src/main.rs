use std::sync::Arc;

use clap::Parser;
use rift_sdk::{create_websocket_provider, DatabaseLocation};
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct HypernodeArgs {
    /// Ethereum RPC websocket URL for indexing and proposing proofs onchain
    #[arg(short, long, env)]
    pub evm_ws_rpc: String,

    /// Bitcoin Core RPC URL for indexing
    #[arg(short, long, env)]
    pub btc_rpc: String,

    /// Ethereum private key for signing hypernode initiated transactions
    #[arg(short, long, env)]
    pub private_key: String,

    /// Database location for MMRs
    #[arg(short, long, env)]
    pub database_location: DatabaseLocation,

    /// Rift Exchange contract address
    #[arg(short, long, env)]
    pub rift_exchange_address: String,

    /// Block number of the deployment of the Rift Exchange contract
    #[arg(short, long, env)]
    pub deploy_block_number: u64,

    /// Location of checkpoint file (bitcoin blocks that are irrevertible)
    #[arg(short, long, env)]
    pub checkpoint_file: String,

    /// Enable mock proof generation
    #[arg(short, long, env, default_value = "false")]
    pub mock_proof: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure logging (optional but recommended)
    let args = HypernodeArgs::parse();

    // create provdier
    let evm_provider = Arc::new(create_websocket_provider(&args.evm_ws_rpc).await?);

    // load irrevertable bitcoin block leaves
    /*

        let contract_data_engine = data_engine::engine::DataEngine::start(
            args.database_location,
            evm_provider,
            args.rift_exchange_address,
            args.deploy_block_number,
            args.checkpoint_leaves,
        )
        .await?;
    */

    println!("Starting hypernode service...");

    Ok(())
}
