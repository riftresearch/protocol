use bitcoin_light_client_core::leaves::{
    decompress_block_leaves, get_genesis_leaf, BlockLeaf, BlockLeafCompressor,
};
use bitcoincore_rpc_async::{Auth, RpcApi};
use checkpoint_downloader::compress_checkpoint_leaves;
use checkpoint_downloader::decompress_checkpoint_file;
use clap::Parser;
use hex;
use rift_sdk::bitcoin_utils::BitcoinClientExt;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::time::Duration;
use tempfile;
use tokio;
use zstd::stream::Encoder;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CheckpointDownloaderArgs {
    /// Bitcoin Core RPC URL for indexing
    #[arg(short, long, env)]
    pub btc_rpc: String,

    /// RPC User
    #[arg(long, env)]
    pub rpc_user: String,

    /// RPC Password
    #[arg(long, env)]
    pub rpc_pass: String,

    /// Chunks per request (concurrency param)
    #[arg(short, long, env)]
    pub chunk_size: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: CheckpointDownloaderArgs = CheckpointDownloaderArgs::parse();
    println!("Checkpoint downloader starting...");

    // [0] Create Bitcoin client with authentication
    let auth = Auth::UserPass(args.rpc_user, args.rpc_pass);
    let client = rift_sdk::bitcoin_utils::AsyncBitcoinClient::new(
        args.btc_rpc,
        auth,
        Duration::from_secs(1),
    )
    .await?;

    // [2] Ensure safe block range
    let safe_end_block = (client.get_block_count().await? - 100) as u32;
    println!("Downloading blocks from 0 to {}", safe_end_block);

    let mut start_block = 0;
    let chunk_size = args.chunk_size;
    let mut all_leaves = Vec::new();

    while start_block <= safe_end_block {
        let end_chunk = std::cmp::min(start_block + chunk_size - 1, safe_end_block);
        println!("Fetching blocks from {} to {}", start_block, end_chunk);

        // [4] Fetch headers from Bitcoin client
        let headers = client
            .get_leaves_from_block_range(start_block, end_chunk, chunk_size as usize, None)
            .await?;
        println!("Retrieved {} headers", headers.len());

        all_leaves.extend(headers);
        start_block = end_chunk + 1;
    }

    // Compress the leaves directly to the final compressed file
    let compressed_filename = "checkpoint_leaves.zst";
    compress_checkpoint_leaves(&all_leaves, compressed_filename)?;

    println!("Compressed checkpoint file saved: {}", compressed_filename);
    println!("Total leaves collected: {}", all_leaves.len());

    Ok(())
}

mod tests {
    use super::*;

    #[test]
    fn test_compress_checkpoint_leaves() {
        let leaves = vec![get_genesis_leaf()];
        // Create a named temporary file
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_str().unwrap();

        compress_checkpoint_leaves(&leaves, temp_path).unwrap();
        let decompressed_leaves = decompress_checkpoint_file(temp_path).unwrap();
        assert_eq!(leaves, decompressed_leaves);
    }
}
