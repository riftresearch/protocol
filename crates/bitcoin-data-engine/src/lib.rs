use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use bitcoincore_rpc_async::bitcoin::{BlockHash, BlockHeader};
use tokio::signal;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use bitcoin_light_client_core::hasher::{Digest, Hasher, Keccak256Hasher};
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::{Auth, Client, RpcApi};
use rift_sdk::bitcoin_utils::BitcoinClientExt;
use rift_sdk::bitcoin_utils::{AsyncBitcoinClient, ChainTipStatus};

use hex;
use rift_sdk::indexed_mmr::IndexedMMR;
use rift_sdk::DatabaseLocation; // assumed to be defined in your code base

/// Our async Bitcoin Data Engine.
/// This struct spawns its own tasks:
///   - The block watchtower syncs the local MMR periodically.
///   - We hold watchers for waiting on specific block heights.
///   - We now also allow subscribing to new blocks as they are appended in the local MMR.
pub struct BitcoinDataEngine {
    /// Our local MMR of the best chain
    pub indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    /// Async RPC client for bitcoind.
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    /// JoinHandle for our block watchtower task.
    block_watchtower_handle: JoinHandle<Result<(), eyre::Report>>,
    /// Map of (block_height -> oneshot Senders), for tasks waiting on that height.
    watchers: Arc<Mutex<HashMap<u32, Vec<oneshot::Sender<BlockLeaf>>>>>,
    /// Collection of watchers waiting for initial sync to complete.
    initial_sync_watchers: Arc<Mutex<Vec<oneshot::Sender<bool>>>>,
    /// Boolean flag to indicate if the initial sync is complete
    initial_sync_complete: Arc<AtomicBool>,

    /// NEW: Broadcast sender for new blocks - supports multiple subscribers
    block_broadcaster: broadcast::Sender<BlockLeaf>,
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

        // Create watchers and initial-sync watchers
        let watchers = Arc::new(Mutex::new(HashMap::new()));
        let initial_sync_watchers = Arc::new(Mutex::new(Vec::new()));
        let initial_sync_complete = Arc::new(AtomicBool::new(false));

        // 100 capacity should be more than enough, consumers will likely handle response instantly
        // and in the case they don't bitcoin blocks come every ~10 minutes
        // so it would take > 16 hours to fill the buffer w/ a capacity of 100
        let (block_broadcaster, _) = broadcast::channel(100);

        // Spawn the block watchtower in a separate task
        let block_watchtower_handle = tokio::spawn(block_watchtower(
            mmr.clone(),
            initial_sync_complete.clone(),
            initial_sync_watchers.clone(),
            watchers.clone(),
            bitcoin_rpc.clone(),
            block_broadcaster.clone(), // pass the broadcaster
            download_chunk_size,
            block_search_interval,
        ));

        Self {
            indexed_mmr: mmr,
            bitcoin_rpc,
            block_watchtower_handle,
            watchers,
            initial_sync_watchers,
            initial_sync_complete,
            block_broadcaster,
        }
    }

    /// NEW: Return a receiver through which the caller will receive all new blocks
    /// whenever they are appended to our local MMR.
    pub fn subscribe_to_new_blocks(&self) -> broadcast::Receiver<BlockLeaf> {
        self.block_broadcaster.subscribe()
    }

    pub async fn wait_for_initial_sync(&self) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();

        // lock channel first, then check if initial sync is complete, then push to channel if not complete
        let mut initial_sync_watchers = self.initial_sync_watchers.lock().await;

        if self
            .initial_sync_complete
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(());
        }

        initial_sync_watchers.push(tx);
        drop(initial_sync_watchers);
        rx.await
            .map_err(|_| eyre::eyre!("Initial sync watcher channel closed unexpectedly"))?;
        Ok(())
    }

    /// Wait for a certain block height to arrive in the MMR. Returns the corresponding `BlockLeaf`.
    pub async fn wait_for_block_height(&self, height: u32) -> eyre::Result<BlockLeaf> {
        // 1. Check if the MMR already has the leaf for this height:
        if let Some(leaf) = {
            let mmr_guard = self.indexed_mmr.read().await;
            mmr_guard.get_leaf_by_leaf_index(height as usize).await?
        } {
            // If it's already there, we can short-circuit return immediately.
            return Ok(leaf);
        }

        // 2. Otherwise, create a oneshot channel and store the Sender in our watchers map.
        let (tx, rx) = oneshot::channel();
        {
            let mut watchers_map = self.watchers.lock().await;
            watchers_map.entry(height).or_default().push(tx);
        }

        // 3. Return the receiving end of the channel.
        rx.await
            .map_err(|_| eyre::eyre!("Block height watcher channel closed unexpectedly"))
    }
}

/// This function is responsible for re-syncing the local MMR with the remote node's best chain
/// on a periodic basis, and then fulfilling watchers for any heights that are now in the MMR.
async fn block_watchtower(
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    initial_sync_complete: Arc<AtomicBool>,
    initial_sync_watchers: Arc<Mutex<Vec<oneshot::Sender<bool>>>>,
    watchers: Arc<Mutex<HashMap<u32, Vec<oneshot::Sender<BlockLeaf>>>>>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,

    // Updated to use broadcast::Sender
    block_broadcaster: broadcast::Sender<BlockLeaf>,

    download_chunk_size: usize,
    block_search_interval: Duration,
) -> Result<(), eyre::Report> {
    loop {
        let (local_best_block_hash, local_leaf_count): (Option<[u8; 32]>, u32) = {
            let local_indexed_mmr = indexed_mmr.read().await;
            let leaf_count = local_indexed_mmr.get_leaf_count().await.unwrap();
            if leaf_count > 0 {
                (
                    Some(
                        local_indexed_mmr
                            .get_leaf_by_leaf_index(leaf_count - 1)
                            .await
                            .unwrap()
                            .unwrap()
                            .block_hash,
                    ),
                    leaf_count as u32,
                )
            } else {
                (None, 0)
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

        let remote_best_block_hash: [u8; 32] = best_block.hash.as_hash().into_inner();
        let remote_best_block_height = best_block.height;

        if local_best_block_hash.is_some()
            && remote_best_block_hash == local_best_block_hash.unwrap()
        {
            // no action needed; they're in sync
        } else {
            // either first sync or a mismatch => find common ancestor, then re-sync
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

            // Download and sync the chain from common_ancestor to remote tip
            if let Err(e) = download_and_sync(
                indexed_mmr.clone(),
                bitcoin_rpc.clone(),
                block_broadcaster.clone(), // Use the broadcaster
                download_start_height,
                remote_best_block_height as u32,
                download_chunk_size,
                common_ancestor_leaf,
            )
            .await
            {
                eprintln!("Error in download_and_sync: {e}");
            }
        }

        // If the initial sync is not complete, set it and notify all watchers
        if !initial_sync_complete.load(std::sync::atomic::Ordering::Relaxed) {
            initial_sync_complete.store(true, std::sync::atomic::Ordering::Relaxed);
            let mut initial_sync_watchers = initial_sync_watchers.lock().await;
            for tx in initial_sync_watchers.drain(..) {
                let _ = tx.send(true);
            }
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
                let _ = tx.send(leaf.clone());
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
/// Now also **broadcasts** them to subscribers as they arrive.
async fn download_and_sync(
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    block_broadcaster: broadcast::Sender<BlockLeaf>,
    start_block_height: u32,
    end_block_height: u32,
    chunk_size: usize,
    parent_leaf: Option<BlockLeaf>,
) -> Result<(), eyre::Report> {
    if let Some(parent) = parent_leaf {
        assert_eq!(start_block_height, parent.height + 1);
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
            .get_leaves_from_block_range(
                current_height,
                end_height,
                chunk_size as usize,
                expected_parent,
            )
            .await
        {
            Ok(ls) => ls,
            Err(e) => {
                return Err(eyre::eyre!("Failed to get leaves: {e}"));
            }
        };

        blocks_processed += leaves.len();

        // Actually append them in the MMR.
        // If it's the first write and we have a parent_leaf, we do `append_or_reorg_based_on_parent`.
        // Otherwise a simple append.
        if first_write && parent_leaf.is_some() {
            let mut combined = vec![parent_leaf.unwrap()];
            combined.extend(&leaves);
            indexed_mmr
                .write()
                .await
                .append_or_reorg_based_on_parent(&combined)
                .await
                .unwrap();
            // ^ only broadcast the newly downloaded blocks (skip the parent's leaf)
            first_write = false;
        } else {
            indexed_mmr
                .write()
                .await
                .batch_append(&leaves)
                .await
                .unwrap();
        }

        if !first_write {
            broadcast_new_blocks(&leaves, block_broadcaster.clone()).await;
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

/// Simple helper: broadcast the newly downloaded blocks to all subscribed receivers.
/// Now using tokio's broadcast channel for efficient 1:many messaging.
async fn broadcast_new_blocks(new_blocks: &[BlockLeaf], broadcaster: broadcast::Sender<BlockLeaf>) {
    for block in new_blocks {
        // With broadcast, we can efficiently send to multiple subscribers
        // It's fine if there are no receivers - send returns how many receivers got the message
        let _ = broadcaster.send(*block);
    }
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
                // if the error is -5 then it means the block does not exist on the remote, so continue searching
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
            .generate_to_address(5, &bitcoin_address)
            .unwrap();

        let data_engine = BitcoinDataEngine::new(
            &db_loc,
            bitcoin_rpc.clone(),
            100,
            Duration::from_millis(250),
        )
        .await;

        // Example: Subscribe to new blocks as they come in
        let mut subscription_rx = data_engine.subscribe_to_new_blocks();

        // Wait for block height 3
        let leaf_for_3 = data_engine.wait_for_block_height(3).await.unwrap();
        println!("Got block at height 3: {:?}", leaf_for_3);

        // Meanwhile, also pull any newly broadcast blocks from `subscription_rx`.
        // In a real app, you'd do this in a separate task/loop:
        if let Ok(new_block) =
            tokio::time::timeout(Duration::from_secs(3), subscription_rx.recv()).await
        {
            println!(
                "Received newly appended block from subscription: {:?}",
                new_block
            );
        }
    }
}
