use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use bitcoincore_rpc_async::bitcoin::BlockHash;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinSet;
use tokio::time::sleep;

use bitcoin_light_client_core::hasher::{Digest, Keccak256Hasher};
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::RpcApi;
use rift_sdk::bitcoin_utils::BitcoinClientExt;
use rift_sdk::bitcoin_utils::{AsyncBitcoinClient, ChainTipStatus};

use rift_sdk::indexed_mmr::IndexedMMR;
use rift_sdk::DatabaseLocation;
use tracing::{error, info, info_span, warn, Instrument}; // assumed to be defined in your code base

/// Our async Bitcoin Data Engine.
/// This struct spawns its own tasks:
///   - The block watchtower syncs the local MMR periodically.
///   - We hold watchers for waiting on specific block heights.
///   - We now also allow subscribing to new blocks as they are appended in the local MMR.
pub struct BitcoinDataEngine {
    /// Our local MMR of the best chain
    pub indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    /// Boolean flag to indicate if the initial sync is complete
    initial_sync_complete: Arc<AtomicBool>,
    /// Broadcast sender for initial sync completion
    initial_sync_broadcaster: broadcast::Sender<bool>,
    /// Broadcast sender for new blocks
    block_broadcaster: broadcast::Sender<BlockLeaf>,
}

impl BitcoinDataEngine {
    /// Create a new data engine.
    pub async fn new(
        database_location: &DatabaseLocation,
        bitcoin_rpc: Arc<AsyncBitcoinClient>,
        download_chunk_size: usize,
        block_search_interval: Duration,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self {
        // Open the IndexedMMR.
        let mmr = Arc::new(RwLock::new(
            IndexedMMR::<Keccak256Hasher>::open(database_location)
                .await
                .expect("Failed to open IndexedMMR"),
        ));

        // Create watchers and initial-sync watchers

        let initial_sync_complete = Arc::new(AtomicBool::new(false));
        let (initial_sync_broadcaster, _) = broadcast::channel(1);

        // 100 capacity should be more than enough, consumers will likely handle response instantly
        // and in the case they don't bitcoin blocks come every ~10 minutes
        // so it would take > 16 hours to fill the buffer w/ a capacity of 100
        let (block_broadcaster, _) = broadcast::channel(100);

        // Spawn the block watchtower in a separate task
        let mmr_clone = mmr.clone();
        let initial_sync_complete_clone = initial_sync_complete.clone();
        let initial_sync_broadcaster_clone = initial_sync_broadcaster.clone();
        let bitcoin_rpc_clone = bitcoin_rpc.clone();
        let block_broadcaster_clone = block_broadcaster.clone();
        join_set.spawn(
            async move {
                block_watchtower(
                    mmr_clone,
                    initial_sync_complete_clone,
                    initial_sync_broadcaster_clone,
                    bitcoin_rpc_clone,
                    block_broadcaster_clone, // pass the broadcaster
                    download_chunk_size,
                    block_search_interval,
                )
                .await
            }
            .instrument(info_span!("BDE Block Watchtower")),
        );

        Self {
            indexed_mmr: mmr,
            initial_sync_complete,
            initial_sync_broadcaster,
            block_broadcaster,
        }
    }

    /// NEW: Return a receiver through which the caller will receive all new blocks
    /// whenever they are appended to our local MMR.
    pub fn subscribe_to_new_blocks(&self) -> broadcast::Receiver<BlockLeaf> {
        self.block_broadcaster.subscribe()
    }

    pub async fn wait_for_initial_sync(&self) -> eyre::Result<()> {
        let mut subscription = self.initial_sync_broadcaster.subscribe();
        match self
            .initial_sync_complete
            .load(std::sync::atomic::Ordering::Acquire)
        {
            true => Ok(()),
            false => {
                subscription.recv().await?;
                Ok(())
            }
        }
    }
}

/// Helper function to retrieve the local tip's hash and the total leaf count
async fn get_local_tip(
    mmr: &RwLock<IndexedMMR<Keccak256Hasher>>,
) -> eyre::Result<(Option<Digest>, u32)> {
    let local_indexed_mmr = mmr.read().await;
    let leaf_count = local_indexed_mmr.get_leaf_count().await?;

    if leaf_count == 0 {
        return Ok((None, 0));
    }

    let tip_block_hash = local_indexed_mmr
        .get_leaf_by_leaf_index(leaf_count - 1)
        .await?
        .ok_or_else(|| eyre::eyre!("Failed to get tip leaf"))?
        .block_hash;

    Ok((Some(tip_block_hash), leaf_count as u32))
}

/// This function is responsible for re-syncing the local MMR with the remote node's best chain
/// on a periodic basis, and then fulfilling watchers for any heights that are now in the MMR.
async fn block_watchtower(
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    initial_sync_complete: Arc<AtomicBool>,
    initial_sync_broadcaster: broadcast::Sender<bool>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    block_broadcaster: broadcast::Sender<BlockLeaf>,
    download_chunk_size: usize,
    block_search_interval: Duration,
) -> Result<(), eyre::Report> {
    info!("Starting block watchtower");
    loop {
        let is_initial_sync_complete =
            initial_sync_complete.load(std::sync::atomic::Ordering::SeqCst);

        // Use the helper function to get local tip information
        let (local_best_block_hash, local_leaf_count) = get_local_tip(&indexed_mmr).await?;

        let chain_tips = bitcoin_rpc.get_chain_tips().await?;

        let best_block = match chain_tips
            .iter()
            .find(|tip| tip.status == ChainTipStatus::Active)
        {
            Some(tip) => tip,
            None => {
                warn!("No active chain tip found, waiting for next sync");
                sleep(block_search_interval).await;
                continue;
            }
        };

        let remote_best_block_hash: [u8; 32] = best_block.hash.as_raw_hash().to_byte_array();
        let remote_best_block_height = best_block.height;

        // If the local best and remote best are the same, we're in sync
        if !local_best_block_hash.is_some_and(|hash| hash == remote_best_block_hash) {
            // either first sync or a mismatch => find common ancestor, then re-sync
            let common_ancestor_leaf = if local_leaf_count > 0 {
                Some(find_common_ancestor_leaf(indexed_mmr.clone(), bitcoin_rpc.clone()).await?)
            } else {
                // it's okay if we don't have a common ancestor but only if we're in initial sync
                if !is_initial_sync_complete {
                    None
                } else {
                    error!("No common ancestor found at all after sync!");
                    return Err(eyre::eyre!("Common Ancestor not found"));
                }
            };

            let download_start_height = common_ancestor_leaf.map_or(0, |leaf| leaf.height + 1);

            // Download and sync the chain from common_ancestor to remote tip
            download_and_sync(
                indexed_mmr.clone(),
                bitcoin_rpc.clone(),
                block_broadcaster.clone(),
                download_start_height,
                remote_best_block_height as u32,
                download_chunk_size,
                common_ancestor_leaf,
                is_initial_sync_complete,
            )
            .await?;
        }

        // If the initial sync is not complete, set it and broadcast
        if !is_initial_sync_complete {
            initial_sync_complete.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = initial_sync_broadcaster.send(true);
            info!("Broadcasted initial sync complete");
        }

        tokio::time::sleep(block_search_interval).await;
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
    initial_sync_complete: bool,
) -> Result<(), eyre::Report> {
    if let Some(parent) = parent_leaf {
        assert_eq!(start_block_height, parent.height + 1);
    }

    let total_blocks = end_block_height.saturating_sub(start_block_height) + 1;
    let start_time = std::time::Instant::now();
    let mut blocks_processed = 0;
    let mut current_height = start_block_height;

    let mut reorged_to_parent = false;

    while current_height <= end_block_height {
        let end_height = std::cmp::min(current_height + chunk_size as u32, end_block_height);

        let expected_parent = if let Some(parent) = parent_leaf.filter(|_| !reorged_to_parent) {
            Some(parent.block_hash)
        } else {
            // Use the helper function to get the tip hash
            let (tip_hash, _) = get_local_tip(&indexed_mmr).await?;
            tip_hash
        };

        let leaves = bitcoin_rpc
            .get_leaves_from_block_range(current_height, end_height, chunk_size, expected_parent)
            .await?;

        blocks_processed += leaves.len();

        // Actually append them in the MMR.
        // If it's the first write and we have a parent_leaf, we do `append_or_reorg_based_on_parent`.
        // Otherwise a simple append.
        if !reorged_to_parent && parent_leaf.is_some() {
            let mut combined = vec![parent_leaf.unwrap()];
            combined.extend(&leaves);
            indexed_mmr
                .write()
                .await
                .append_or_reorg_based_on_parent(&combined)
                .await?;
            reorged_to_parent = true;
        } else {
            indexed_mmr.write().await.batch_append(&leaves).await?;
        }

        // Only broadcast new blocks after initial sync is complete
        if initial_sync_complete {
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

async fn broadcast_new_blocks(new_blocks: &[BlockLeaf], broadcaster: broadcast::Sender<BlockLeaf>) {
    for block in new_blocks {
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
    let (_, local_leaf_count) = get_local_tip(&indexed_mmr).await?;
    assert!(local_leaf_count > 0);

    let mut current_leaf_index = local_leaf_count as usize - 1;

    loop {
        let best_block_leaf = indexed_mmr
            .read()
            .await
            .get_leaf_by_leaf_index(current_leaf_index)
            .await?
            .ok_or_else(|| eyre::eyre!("Could not find leaf @ index {current_leaf_index}"))?;

        let mut block_hash = best_block_leaf.block_hash;
        block_hash.reverse();

        let header_request = bitcoin_rpc
            .get_block_header_info(&BlockHash::from_slice(&block_hash)?)
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

    info!(
        "Progress: {}/{} blocks ({:.1}%) - Downloaded {} headers - ETA: {:.1}s",
        processed, total, percentage, processed, eta
    );
}
