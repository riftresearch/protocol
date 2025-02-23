use std::time::Duration;

use bitcoin_light_client_core::leaves::{create_new_leaves, BlockLeaf};
use bitcoincore_rpc_async::{Auth, Client as BitcoinClient, RpcApi};
use clap::Parser;
use rift_sdk::bitcoin_utils::BitcoinClientExt;
use tokio;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CheckpointDownloaderArgs {
    /// Bitcoin Core RPC URL for indexing
    #[arg(short, long, env)]
    pub btc_rpc: String,

    /// Bitcoin block height to stop downloading at (inclusive)
    #[arg(short, long, env)]
    pub end_block: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CheckpointDownloaderArgs::parse();

    println!("Checkpoint downloader starting...");

    let client = rift_sdk::bitcoin_utils::AsyncBitcoinClient::new(
        args.btc_rpc,
        Auth::None,
        Duration::from_secs(1),
    )
    .await?;

    let blockchain_info = client.get_block_header_info(0 as u32).await?;
    println!("Blockchain info: {:?}", blockchain_info);

    let genesis_leaf = bitcoin_light_client_core::leaves::get_genesis_leaf();

    let leaves = create_new_leaves(&genesis_leaf, &[], &[]);

    Ok(())
}
