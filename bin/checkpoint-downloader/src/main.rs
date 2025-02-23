use bitcoin_light_client_core::leaves::{get_genesis_leaf, BlockLeaf};
use bitcoincore_rpc_async::{Auth, RpcApi};
use clap::Parser;
use hex;
use rift_sdk::bitcoin_utils::BitcoinClientExt;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::time::Duration;
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

    /// Bitcoin block height to stop downloading at (inclusive)
    #[arg(short, long, env)]
    pub end_block: u32,
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

    // [1] Get genesis leaf
    let _genesis_leaf: BlockLeaf = get_genesis_leaf();

    // [2] Ensure safe block range (100 blocks before the end block to prevent reorgs)
    let safe_end_block = args.end_block.saturating_sub(100);
    println!("Downloading blocks from 0 to {}", safe_end_block);

    let mut start_block = 0;
    let chunk_size = 1000;
    let checkpoint_filename = "checkpoint_leaves.txt";

    // If this is the first time running, overwrite the file.
    if start_block == 0 {
        File::create(checkpoint_filename)?; // This clears the file on a fresh run
    }

    // Open file in append mode for adding new chunks
    let mut checkpoint_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(checkpoint_filename)?;

    while start_block <= safe_end_block {
        let end_chunk = std::cmp::min(start_block + chunk_size - 1, safe_end_block);
        println!("Fetching blocks from {} to {}", start_block, end_chunk);

        // [4] Fetch headers from Bitcoin client
        let headers = client
            .get_leaves_from_block_range(start_block, end_chunk, None, None)
            .await?;
        println!("Retrieved {} headers", headers.len());

        // [5] Write headers to the file in hex format
        let mut writer = BufWriter::new(&checkpoint_file);
        for header in headers {
            writeln!(writer, "{}", hex::encode(header.serialize()))?;
        }
        writer.flush()?;

        start_block = end_chunk + 1; // Move to next chunk
    }

    println!("Checkpoint file saved: {}", checkpoint_filename);

    // [6] Compress checkpoint file using Zstd
    let compressed_filename = "checkpoint_leaves.zst";
    let input_file = File::open(checkpoint_filename)?;
    let output_file = File::create(compressed_filename)?;
    let mut encoder = Encoder::new(output_file, 0)?; // Compression level 0 (default)
    let mut reader = BufReader::new(input_file);
    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;

    println!("Compressed checkpoint file saved: {}", compressed_filename);

    Ok(())
}
