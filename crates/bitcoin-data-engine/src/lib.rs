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
//!
//! This file now also demonstrates how to watch for a specific block height:
//!   - We maintain a map of (block_height -> Vec<oneshot::Sender<BlockLeaf>>).
//!   - `wait_for_block_height` checks if the height is already in the MMR. If yes, short-circuits. If not,
//!     it registers a watcher (oneshot sender) into that map.
//!   - After each sync pass in the watchtower, we fulfill watchers for any height that became available.
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use bitcoincore_rpc_async::bitcoin::{BlockHash, BlockHeader};
use tokio::signal;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
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
///
///   - We also hold a watchers map that allows consumers to wait on specific heights.
///     Each entry is (height -> vec of oneshot::Sender<BlockLeaf>). Once we discover that
///     height is in the MMR, we fulfill all watchers for that height.
pub struct BitcoinDataEngine {
    /// Our local MMR of the best chain
    pub indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    /// Tokio mpsc channel for blocks downstream consumer should analyze (new blocks)
    blocks_to_analyze_tx: mpsc::UnboundedSender<()>,
    blocks_to_analyze_rx: mpsc::UnboundedReceiver<()>,
    /// Async RPC client for bitcoind.
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    /// JoinHandle for our block watchtower task.
    block_watchtower_handle: JoinHandle<Result<(), eyre::Report>>,
    /// Map of (block_height -> oneshot Senders), for tasks waiting on that height.
    watchers: Arc<Mutex<HashMap<u32, Vec<oneshot::Sender<BlockLeaf>>>>>,
}

impl BitcoinDataEngine {
    /// Create a new data engine.
    pub async fn new(
        database_location: &DatabaseLocation,
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

        // Create a watchers map for waiting on specific heights
        let watchers = Arc::new(Mutex::new(HashMap::new()));

        // Spawn the block watchtower in a separate task
        let block_watchtower_handle = tokio::spawn(block_watchtower(
            mmr.clone(),
            watchers.clone(),
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
            watchers,
        }
    }

    /// Wait for a certain block height to arrive in the MMR. Returns the corresponding `BlockLeaf`.
    pub async fn wait_for_block_height(&self, height: u32) -> eyre::Result<BlockLeaf> {
        // 1. Check if the MMR already has the leaf for this height:
        if let Some(leaf) = {
            // Assume you have a method like `find_leaf_by_block_height` in your MMR or a trait extension:
            let mmr_guard = self.indexed_mmr.read().await;
            mmr_guard.get_leaf_by_leaf_index(height as usize).await?
        } {
            // If it's already there, we can short-circuit immediately.
            return Ok(leaf);
        }

        // 2. Otherwise, create a oneshot channel and store the Sender in our watchers map.
        let (tx, rx) = oneshot::channel();
        {
            let mut watchers_map = self.watchers.lock().await;
            watchers_map.entry(height).or_default().push(tx);
        }

        // 3. Return the receiving end of the channel. When the watchtower loop
        //    sees that this height arrived, it will send the corresponding `BlockLeaf`.
        rx.await.map_err(|_| eyre::eyre!("oneshot canceled"))
    }
}

/// This function is responsible for re-syncing the local MMR with the remote node's best chain
/// on a periodic basis, and then fulfilling watchers for any heights that are now in the MMR.
async fn block_watchtower(
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    watchers: Arc<Mutex<HashMap<u32, Vec<oneshot::Sender<BlockLeaf>>>>>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    // number of blocks to download at a time before applying to the local mmr
    download_chunk_size: usize,
    // how often to check for a new best block
    block_search_interval: Duration,
) -> Result<(), eyre::Report> {
    loop {
        let (local_best_block_hash, local_leaf_count): (Option<[u8; 32]>, u32) = {
            let local_indexed_mmr = indexed_mmr.read().await;
            let local_leaf_count = local_indexed_mmr.get_leaf_count().await.unwrap();
            // println!("Local leaf count: {:?}", local_leaf_count);

            if local_leaf_count > 0 {
                (
                    Some(
                        local_indexed_mmr
                            .get_leaf_by_leaf_index(local_leaf_count - 1)
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

        let chain_tips = match bitcoin_rpc.get_chain_tips().await {
            Ok(tips) => tips,
            Err(e) => {
                eprintln!("Error getting chain tips: {e}");
                sleep(block_search_interval).await;
                continue;
            }
        };

        let best_block = match chain_tips
            .iter()
            .find(|tip| tip.status == ChainTipStatus::Active)
        {
            Some(tip) => tip,
            None => {
                eprintln!("No active chain tip found");
                sleep(block_search_interval).await;
                continue;
            }
        };

        // println!("Best chain tip: {:?}", best_block);

        let remote_best_block_hash: [u8; 32] = best_block.hash.as_hash().into_inner();
        let remote_best_block_height = best_block.height;

        if local_best_block_hash.is_some()
            && remote_best_block_hash == local_best_block_hash.unwrap()
        {
            // println!("Local and remote fully synced");
        } else {
            // determine if we need to reorg any local blocks
            // at this point all we know is the local block hash and the remote best block hash are different
            // so we need to find the common ancestor

            // this is the leaf that we know about on the local chain, start from here when downloading + syncing
            let common_ancestor_leaf = if local_leaf_count > 0 {
                Some(
                    find_common_ancestor_leaf(indexed_mmr.clone(), bitcoin_rpc.clone())
                        .await
                        .unwrap(),
                )
            } else {
                None
            };

            let download_start_height = common_ancestor_leaf.map_or(0, |leaf| leaf.height + 1);

            // Get the headers for the blocks since the common ancestor
            download_and_sync(
                indexed_mmr.clone(),
                bitcoin_rpc.clone(),
                download_start_height,
                remote_best_block_height as u32,
                download_chunk_size,
                common_ancestor_leaf,
            )
            .await
            .unwrap();
        }

        // **After** re-syncing, check if any watchers can now be fulfilled.
        fulfill_watchers(&indexed_mmr, &watchers).await;

        tokio::time::sleep(block_search_interval).await;
    }
}

/// Once we've updated our MMR, we look to see if any watchers can now be fulfilled.
async fn fulfill_watchers(
    indexed_mmr: &Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    watchers: &Arc<Mutex<HashMap<u32, Vec<oneshot::Sender<BlockLeaf>>>>>,
) {
    let mut watchers_map = watchers.lock().await;
    let mut fulfilled_heights = Vec::new();

    // We'll gather all watchers that can be fulfilled now.
    for (height, senders) in watchers_map.iter_mut() {
        // If the MMR already has this block, send it!
        if let Some(leaf) = indexed_mmr
            .read()
            .await
            .get_leaf_by_leaf_index(*height as usize)
            .await
            .unwrap()
        {
            // Fulfill all watchers for this height.
            for tx in senders.drain(..) {
                let _ = tx.send(leaf);
            }
            // We'll remove this entry afterward.
            fulfilled_heights.push(*height);
        }
    }

    // Remove the fulfilled heights from the map so we don't keep them around.
    for h in fulfilled_heights {
        watchers_map.remove(&h);
    }
}

/// Download and sync new blocks starting from `start_block_height` to `end_block_height`.
async fn download_and_sync(
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    start_block_height: u32,
    end_block_height: u32,
    chunk_size: usize,
    parent_leaf: Option<BlockLeaf>,
) -> Result<(), eyre::Report> {
    if parent_leaf.is_some() {
        assert!(start_block_height == parent_leaf.unwrap().height + 1);
    }

    let total_blocks = end_block_height.saturating_sub(start_block_height) + 1;
    let start_time = std::time::Instant::now();
    let mut blocks_processed = 0;
    let mut current_height = start_block_height;
    let mut first_write = true;

    while current_height <= end_block_height {
        let end_height = std::cmp::min(current_height + chunk_size as u32, end_block_height);

        let expected_parent = if first_write && parent_leaf.is_some() {
            Some(parent_leaf.unwrap().block_hash)
        } else {
            let mmr = indexed_mmr.read().await;
            let leaf_count = mmr.get_leaf_count().await?;
            if leaf_count == 0 {
                None
            } else {
                Some(
                    mmr.get_leaf_by_leaf_index(leaf_count - 1)
                        .await?
                        .ok_or_else(|| eyre::eyre!("Failed to get tip leaf"))?
                        .block_hash,
                )
            }
        };

        let leaves = match bitcoin_rpc
            .get_leaves_from_block_range(current_height, end_height, None, expected_parent)
            .await
        {
            Ok(ls) => ls,
            Err(e) => {
                return Err(eyre::eyre!("Failed to get leaves: {e}"));
            }
        };

        blocks_processed += leaves.len();

        // TODO: Include safety check to ensure that each leaf's prev_hash is the same as the previous leaf's block_hash
        // before appending to the MMR

        if first_write && parent_leaf.is_some() {
            // do a reorg and write for the first chunk
            let mut combined = vec![parent_leaf.unwrap()];
            combined.extend(leaves);
            indexed_mmr
                .write()
                .await
                .append_or_reorg_based_on_parent(&combined)
                .await
                .unwrap();
            first_write = false;
        } else {
            indexed_mmr
                .write()
                .await
                .batch_append(&leaves)
                .await
                .unwrap();
        }

        display_progress(
            blocks_processed,
            total_blocks as usize,
            start_time.elapsed(),
        );
        current_height = end_height + 1;
    }

    Ok(())
}

enum BlockStatus {
    InChain(BlockLeaf),
    NotInChain,
}

/// Find the highest local block that is still in the remote chain, i.e. a common ancestor.
async fn find_common_ancestor_leaf(
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
) -> Result<BlockLeaf, eyre::Report> {
    // Start at the local best block and query its header to ensure its confirmations are >= 0.
    // If the confirmations are < 0, we need to roll back the local MMR by continuing to search backwards.
    let local_leaf_count = indexed_mmr.read().await.get_leaf_count().await.unwrap();
    assert!(local_leaf_count > 0);

    let mut current_leaf_index = local_leaf_count - 1;

    loop {
        let best_block_leaf = indexed_mmr
            .read()
            .await
            .get_leaf_by_leaf_index(current_leaf_index)
            .await
            .unwrap()
            .ok_or_else(|| eyre::eyre!("Could not find leaf @ index {current_leaf_index}"))?;

        let mut block_hash = best_block_leaf.block_hash;
        block_hash.reverse();

        let header_request = bitcoin_rpc
            .get_block_header_info(&BlockHash::from_slice(&block_hash).unwrap())
            .await;

        let header_status = match header_request {
            Ok(header_info) => {
                if header_info.confirmations == -1 {
                    Ok(BlockStatus::NotInChain)
                } else {
                    Ok(BlockStatus::InChain(best_block_leaf))
                }
            }
            Err(bitcoincore_rpc_async::Error::JsonRpc(
                bitcoincore_rpc_async::jsonrpc::error::Error::Rpc(ref rpcerr),
            )) if rpcerr.code == -5 => {
                // if the error is -5 rpc error then it means the block does not exist on the remote, so continue searching
                Ok(BlockStatus::NotInChain)
            }
            _ => Err(header_request.unwrap_err()),
        }
        .map_err(|e| eyre::eyre!("Get block header info failed: {e}"))?;

        match header_status {
            BlockStatus::InChain(block_leaf) => {
                return Ok(block_leaf);
            }
            BlockStatus::NotInChain => {
                // continue searching backwards
                if current_leaf_index == 0 {
                    return Err(eyre::eyre!("No common ancestor found at all!"));
                }
                current_leaf_index -= 1;
            }
        }
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
    async fn test_wait_for_block_height() {
        let db_loc = DatabaseLocation::InMemory;
        let (bitcoin_regtest, bitcoin_rpc, bitcoin_address) =
            setup_bitcoin_regtest_and_client().await;
        let bitcoin_rpc = Arc::new(bitcoin_rpc);

        // mine some blocks
        bitcoin_regtest
            .client
            .generate_to_address(101, &bitcoin_address) // 5 is the new tip after this
            .unwrap();

        println!("Workdir: {:?}", bitcoin_regtest.workdir());

        let data_engine = BitcoinDataEngine::new(
            &db_loc,
            bitcoin_rpc.clone(),
            100,
            Duration::from_millis(250),
        )
        .await;
        println!(
            "Current height according to regtest: {:?}",
            (bitcoin_rpc.get_block_count().await.unwrap())
        );
        println!("Waiting for block height 6");
        let tip_leaf = data_engine.wait_for_block_height(5).await.unwrap();
        println!("[post]Tip leaf: {:?}", tip_leaf);
        let leaf_count = data_engine
            .indexed_mmr
            .read()
            .await
            .get_leaf_count()
            .await
            .unwrap();
        println!("[post]Leaf count: {:?}", leaf_count);
    }

    #[tokio::test]
    async fn test_call_get_block_header_info_non_existant_header() {

        /*
        let (bitcoin_regtest, bitcoin_rpc, _) = setup_bitcoin_regtest_and_client().await;

        println!("Bitcoin rpc: {:?}", bitcoin_regtest.rpc_url());
        println!("Cookie: {:?}", bitcoin_regtest.params.cookie_file);
        let mut cookie = String::new();
        File::open(bitcoin_regtest.params.cookie_file.clone())
            .await
            .unwrap()
            .read_to_string(&mut cookie)
            .await
            .unwrap();

        println!("curl -X POST --user \"{}\" --data-binary '{{\"jsonrpc\":\"1.0\",\"id\":\"curl\",\"method\":\"getblockheader\",\"params\":[\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed00\"]}}' -H 'content-type: text/plain;' http://127.0.0.1:61386/ | jq", cookie);
        println!("Press ctrl+c to continue");
        signal::ctrl_c().await.unwrap();

        let resp = bitcoin_rpc
            .get_block_header_info(&BlockHash::from_slice(&[0u8; 32]).unwrap())
            .await;
        println!("{:?}", resp);
        */
    }
}
