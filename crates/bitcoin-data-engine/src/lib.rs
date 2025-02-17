/*
Bitcoin Data Engine
    Features:
        - Notifications on new blocks to consumers
        - MMR storage of the best chain locally
        - Optimized block header download
        - Safely get block data from bitcoind, with retries and backoff (irrelevant to consumer)

    Thread 2 starts first then Thread 1 immediately after

    block_notif: Boolean flag to indicate if the block notifier has seen a block since the thread has updated it.

    Thread 1:
        Grab best block hash from local mmr (or nothing if first run)
        -> If first run, download all block headers from bitcoind (not actually headers though, we have an optimized function for this)
        -> If not first run, download headers from bitcoind for all blocks since the last block in the mmr

        Apply these headers to the local mmr

        then subscribing to the block_notif being true:
            block_notif is set to false
            Call getblockchaininfo on bitcoind to get the best chain hash + height
            Call getblockheader with the local chain best hash @ `n` height
            -> If the header confirmations < 0, then this block has been reorged and we need to keep searching
            -> if the header confirmations >= 0, then this block is part of the best chain so we can build from this block (call this the safe block), also store how many heights between the safe
               block and the local mmr best block exist, so we know many blocks to rollback. (call this the rollback delta)
            Determine the height range between the safe block and the real best block, download the headers for this range
            In an atomic operation, rollback the MMR by the rollback delta, and add the new headers to the MMR
            [Local MMR Chain is now the best chain according to bitcoind]
            Continue to subscribe to the block_notif being true


    Thread 2:
    -> Connect to bitcoind over zeromq, subscribe to new block headers
    -> Extract the block and send it to consumers
    -> Set the block_notif flag to true



*/
//! data_engine_with_indexed_mmr.rs
//!
//! A demonstration of how to integrate your `IndexedMMR<Keccak256Hasher>`
//! in a multi-threaded "data engine" design, where:
//!   - Thread 2 (ZMQ listener) sees new block announcements and sets a `block_notif` flag.
//!   - Thread 1 (sync thread) detects that flag and re-syncs the local MMR by comparing our best tip
//!     to bitcoind's best chain, performing `reorg` or new `append`s as needed.
use std::convert::TryInto;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use tokio::signal;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use bitcoin_light_client_core::hasher::{Digest, Hasher, Keccak256Hasher};
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::{Auth, Client, RpcApi};
use rift_sdk::bitcoin_utils::BitcoinClientExt;
use rift_sdk::bitcoin_utils::{AsyncBitcoinClient, ChainTipStatus};

use hex;
use rift_sdk::mmr::IndexedMMR;
use rift_sdk::DatabaseLocation; // assumed to be defined in your code base

/// Our async Bitcoin Data Engine.
/// This struct spawns its own tasks:
///   - The publisher ("Bitcoin Block Watch Tower") sends new-block signals via a channel.
pub struct BitcoinDataEngine {
    /// Our local MMR of the best chain
    pub indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    /// Tokio mpsc channel for blocks downstream consumer should analyze (new blocks)
    blocks_to_analyze_tx: mpsc::UnboundedSender<()>,
    blocks_to_analyze_rx: mpsc::UnboundedReceiver<()>,
    /// Async RPC client for bitcoind.
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    /// JoinHandle for our block watchtower task.
    block_watchtower_handle: JoinHandle<()>,
}

impl BitcoinDataEngine {
    /// Create a new data engine.
    pub async fn new(
        database_location: DatabaseLocation,
        bitcoin_rpc: Arc<AsyncBitcoinClient>,
        download_chunk_size: usize,
        block_search_interval: Duration,
    ) -> Self {
        // Open the IndexedMMR.
        let mmr = Arc::new(RwLock::new(
            IndexedMMR::<Keccak256Hasher>::open(database_location)
                .await
                .expect("Failed to open IndexedMMR"),
        ));

        let (blocks_to_analyze_tx, blocks_to_analyze_rx) = tokio::sync::mpsc::unbounded_channel();

        // Spawn the block watchtower in a separate task
        let block_watchtower_handle = tokio::spawn(block_watchtower(
            mmr.clone(),
            bitcoin_rpc.clone(),
            download_chunk_size,
            block_search_interval,
        ));

        Self {
            indexed_mmr: mmr,
            blocks_to_analyze_tx,
            blocks_to_analyze_rx,
            bitcoin_rpc,
            block_watchtower_handle,
        }
    }
}

async fn download_and_sync(
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    start_block_height: u32,
    end_block_height: u32,
    chunk_size: usize,
) {
    let total_blocks = end_block_height.saturating_sub(start_block_height) + 1;
    let start_time = std::time::Instant::now();
    let mut blocks_processed = 0;
    let mut current_height = start_block_height;

    while current_height <= end_block_height {
        let end_height = std::cmp::min(current_height + chunk_size as u32, end_block_height);
        let leaves = bitcoin_rpc
            .get_leaves_from_block_range(current_height, end_height, None)
            .await
            .expect("Failed to get leaves");

        // Apply the headers to the local mmr
        indexed_mmr
            .write()
            .await
            .batch_append(&leaves)
            .await
            .unwrap();

        blocks_processed += leaves.len();

        // Calculate estimated time remaining
        let elapsed = start_time.elapsed();

        display_progress(blocks_processed, total_blocks as usize, elapsed);

        current_height = end_height + 1; // +1 because we want to start at the next block
    }
}

async fn rollback_to_common_ancestor(
    local_best_block_hash: [u8; 32],
    local_best_block_height: u32,
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
) {
    // Start at the local best block and query its header to ensure its confirmations are >= 0.
    // If the confirmations are < 0, we need to roll back the local MMR by the number of missing confirmations.
    // The most efficient strategy is to first download the local best block header; in most cases,
    // its confirmations will be >= 0 and we can simply return the local best block as the common ancestor.
    // However, if the confirmations are insufficient, download a chunk of block headers by hash (of size `n`)
    // from the indexed MMR in reverse order until you find a block with confirmations >= 0.
    // This block is the common ancestor to which we should roll back.

    let common_ancestor = bitcoin_rpc
        .get_common_ancestor(local_best_block_hash, remote_best_block_hash)
        .await
        .unwrap();
    common_ancestor
}

async fn block_watchtower(
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    // number of blocks to download at a time before applying to the local mmr
    download_chunk_size: usize,
    // how often to check for a new best block
    block_search_interval: Duration,
) {
    loop {
        // Scope the lock to automatically drop it when we're done
        let (local_best_block_hash, local_leaf_count): (Option<[u8; 32]>, u32) = {
            let local_indexed_mmr = indexed_mmr.read().await;
            let local_leaf_count = local_indexed_mmr.get_leaf_count().await.unwrap();
            println!("Local leaf count: {:?}", local_leaf_count);

            if local_leaf_count > 0 {
                (
                    Some(
                        local_indexed_mmr
                            .find_leaf_by_leaf_index(local_leaf_count - 1)
                            .await
                            .unwrap()
                            .unwrap()
                            .block_hash,
                    ),
                    local_leaf_count as u32,
                )
            } else {
                (None, local_leaf_count as u32)
            }
        };

        let chain_tips = bitcoin_rpc.get_chain_tips().await.unwrap();

        let best_block = chain_tips
            .iter()
            .find(|tip| tip.status == ChainTipStatus::Active)
            .expect("No active chain tip found");

        println!("Best chain tip: {:?}", best_block);

        let remote_best_block_hash: [u8; 32] = best_block.hash.as_hash().into_inner();
        let remote_best_block_height = best_block.height;

        if local_best_block_hash.is_some()
            && remote_best_block_hash == local_best_block_hash.unwrap()
        {
            println!("Local and remote fully synced");
        } else {
            // determine if we need to reorg any local blocks
            // at this point all we know is the local block hash and the remote best block hash are different
            // so we need to find the common ancestor
            let common_ancestor = bitcoin_rpc
                .get_common_ancestor(local_best_block_hash.unwrap(), remote_best_block_hash)
                .await
                .unwrap();
            // Get the headers for the blocks since the local best block
            download_and_sync(
                indexed_mmr.clone(),
                bitcoin_rpc.clone(),
                local_leaf_count,
                remote_best_block_height as u32,
                download_chunk_size,
            )
            .await;
        }
        tokio::time::sleep(block_search_interval).await;
    }
}

fn display_progress(processed: usize, total: usize, elapsed: std::time::Duration) {
    let percentage = (processed as f64 / total as f64 * 100.0).min(100.0);
    let blocks_per_sec = processed as f64 / elapsed.as_secs_f64();
    let remaining = total.saturating_sub(processed);
    let eta = if blocks_per_sec > 0.0 {
        remaining as f64 / blocks_per_sec
    } else {
        f64::INFINITY
    };

    println!(
        "Progress: {}/{} blocks ({:.1}%) - Downloaded {} headers - ETA: {:.1}s",
        processed, total, percentage, processed, eta
    );
}

#[cfg(test)]
mod tests {

    use super::*;
    use corepc_node::client::bitcoin::Address as BitcoinAddress;
    use corepc_node::{types::GetTransaction, Client as BitcoinClient, Node as BitcoinRegtest};
    use tokio::signal;

    async fn setup_bitcoin_regtest_and_client(
    ) -> (BitcoinRegtest, AsyncBitcoinClient, BitcoinAddress) {
        let bitcoin_regtest = BitcoinRegtest::from_downloaded().unwrap();
        let cookie = bitcoin_regtest.params.cookie_file.clone();
        let bitcoin_address = bitcoin_regtest
            .create_wallet("alice")
            .unwrap()
            .new_address()
            .unwrap();
        let bitcoin_rpc_url = bitcoin_regtest.rpc_url();
        let bitcoin_rpc = AsyncBitcoinClient::new(
            bitcoin_rpc_url,
            Auth::CookieFile(cookie.clone()),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
        (bitcoin_regtest, bitcoin_rpc, bitcoin_address)
    }

    #[tokio::test]
    async fn test_download_and_sync() {
        let db_loc = DatabaseLocation::InMemory;
        let (bitcoin_regtest, bitcoin_rpc, bitcoin_address) =
            setup_bitcoin_regtest_and_client().await;

        // mine some blocks
        bitcoin_regtest
            .client
            .generate_to_address(15, &bitcoin_address)
            .unwrap();

        println!("Workdir: {:?}", bitcoin_regtest.workdir());

        let data_engine = BitcoinDataEngine::new(
            db_loc,
            Arc::new(bitcoin_rpc),
            100,
            Duration::from_millis(250),
        )
        .await;
        signal::ctrl_c().await.unwrap();
    }
}
