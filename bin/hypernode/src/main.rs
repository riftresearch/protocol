use bitcoin_light_client_core::leaves::BlockLeaf;
use clap::Parser;
use rift_sdk::{create_websocket_provider, DatabaseLocation};
use serde_json;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;
use tokio::runtime::Runtime;
use zip::read::ZipArchive;

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
    // [0] configure logging (optional but recommended)
    let args = HypernodeArgs::parse();

    // [1] create provider
    let evm_provider = Arc::new(create_websocket_provider(&args.evm_ws_rpc).await?);

    // [2] load irrevertable bitcoin block leaves from checkpoint zip file
    let file = File::open(&args.checkpoint_file)?;
    let mut zip = ZipArchive::new(BufReader::new(file))?;

    // [3] extract the JSON file from the zip archive
    let mut leaves_json = String::new();
    let mut file_in_zip = zip.by_name("leaves.json")?;
    file_in_zip.read_to_string(&mut leaves_json)?;

    // [4] deserialize JSON into Vec<BlockLeaf>
    let checkpoint_leaves: Vec<BlockLeaf> = serde_json::from_str(&leaves_json)?;
    println!(
        "Loaded {} checkpoint leaves from zip file",
        checkpoint_leaves.len()
    );

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
