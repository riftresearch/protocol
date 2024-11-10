use alloy::primitives::U256;
use futures::stream::{StreamExt, TryStreamExt};
use futures_util::stream;
use rift_core::constants::MAX_BLOCKS;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::{hashes::Hash, hex::DisplayHex, opcodes::all::OP_RETURN, script::Builder, Block};
use log::{debug, info};

use crate::{
    btc_rpc::BitcoinRpcClient,
    constants::{CHECKPOINT_BLOCK_INTERVAL, CONFIRMATION_HEIGHT_DELTA},
    core::ThreadSafeStore,
    error::HypernodeError,
    hyper_err, proof_builder, Result,
};

fn build_rift_inscription(order_nonce: [u8; 32]) -> Vec<u8> {
    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&order_nonce)
        .into_script()
        .into_bytes()
}

async fn analyze_block_for_payments(
    height: u64,
    block: &Block,
    active_reservations: Arc<ThreadSafeStore>,
) -> Result<()> {
    let expected_order_inscriptions = active_reservations
        .with_lock(|reservations_guard| {
            reservations_guard
                .reservations
                .iter()
                .map(|(id, metadata)| {
                    let script = build_rift_inscription(metadata.reservation.nonce.0);
                    (id.clone(), script)
                })
                .collect::<Vec<_>>()
        })
        .await;

    for tx in block.txdata.iter() {
        for script in tx.output.iter().map(|out| out.script_pubkey.clone()) {
            for (id, expected_script) in expected_order_inscriptions.iter() {
                if script.as_bytes() == expected_script {
                    info!(
                        "Found payment for reservation: {}, txid: {} at block height: {}",
                        id,
                        tx.compute_txid(),
                        height
                    );
                    active_reservations
                        .with_lock(|reservations_guard| {
                            reservations_guard.update_btc_reservation_initial(
                                *id,
                                height,
                                *block.block_hash().as_raw_hash().as_byte_array(),
                                *tx.compute_txid().as_byte_array(),
                            );
                        })
                        .await;
                }
            }
        }
    }

    Ok(())
}

async fn analyze_reservations_for_sufficient_confirmations(
    height: u64,
    block: &Block,
    active_reservations: Arc<ThreadSafeStore>,
    rpc_client: &BitcoinRpcClient,
    proof_gen_queue: Arc<proof_builder::ProofGenerationQueue>,
) -> Result<()> {
    let pending_confirmation_reservations = active_reservations
        .with_lock(|reservations_guard| {
            reservations_guard
                .reservations
                .iter()
                .filter_map(|(id, metadata)| {
                    (metadata.btc_initial.as_ref().is_some()
                        && metadata.btc_final.as_ref().is_none())
                    .then(|| Some((id.clone(), metadata.clone())))
                    .unwrap_or(None)
                })
                .collect::<Vec<_>>()
        })
        .await;

    let header_contract_btc_block_hashes = active_reservations
        .with_lock(|reservations_guard| reservations_guard.safe_contract_block_hashes.clone())
        .await;

    let mut available_btc_heights = header_contract_btc_block_hashes.keys().collect::<Vec<_>>();
    available_btc_heights.sort();

    for (id, reservation_metadata) in pending_confirmation_reservations {
        let btc_initial_metadata = reservation_metadata.btc_initial.unwrap();
        if btc_initial_metadata.proposed_block_height + CONFIRMATION_HEIGHT_DELTA > height {
            info!(
                "Reservation: {} not confirmed yet, need {} more confirmations",
                id,
                btc_initial_metadata.proposed_block_height + CONFIRMATION_HEIGHT_DELTA - height
            );
            // not enough confirmations yet
            continue;
        }
        // If here, this reservation can be considered confirmed, it's confirmation height may be
        // behind the current tip so in that case, we need to find the closest available block to
        // the right of the proposed block height + CONFIRMATION_HEIGHT_DELTA (min of 5)
        // use binary search to find an available block height that is greater than or equal to the proposed block height
        let safe_height_index = match available_btc_heights
            .binary_search(&&btc_initial_metadata.proposed_block_height)
        {
            Ok(index) => index - 1,
            Err(index) => index - 1,
        };
        let safe_height = available_btc_heights[safe_height_index];

        let min_confirmation_height =
            btc_initial_metadata.proposed_block_height + CONFIRMATION_HEIGHT_DELTA;

        // it's possible that the actual btc chain has enough confirmations but the contract chain
        // does not, in that case, we provide the actual + CONFIRMATION_HEIGHT_DELTA block as the
        // confirmation height b/c the contract chain doesn't have enough blocks yet
        let confirmation_height =
            match available_btc_heights.binary_search(&&min_confirmation_height) {
                Ok(index) => available_btc_heights[index],
                Err(index) => {
                    if index == available_btc_heights.len() {
                        // All available heights are smaller than min_confirmation_height
                        &min_confirmation_height
                    } else {
                        // The closest available height to the right of min_confirmation_height
                        available_btc_heights[index]
                    }
                }
            };

        debug!(
            "Min Confirmation Height: {}, reservation: {}",
            min_confirmation_height, id
        );
        debug!(
            "Confirmation Height: {}, reservation: {}",
            confirmation_height, id
        );

        let btc_rpc = rpc_client;
        let blocks: Vec<Block> = stream::iter(*safe_height..*confirmation_height + 1)
            .map(move |height| async move {
                let block_hash = btc_rpc.get_block_hash(height).await.map_err(|e| {
                    hyper_err!(
                        RpcError,
                        "Failed to get block hash for height {}: {}",
                        height,
                        e
                    )
                })?;

                let block = btc_rpc.get_block(&block_hash).await.map_err(|e| {
                    hyper_err!(
                        RpcError,
                        "Failed to get block for hash {}: {}",
                        block_hash.to_hex_string(bitcoin::hex::Case::Lower),
                        e
                    )
                })?;
                Ok(block)
            })
            .buffered(10)
            .collect::<Vec<Result<Block>>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

        let blocks = blocks.into_iter().collect::<Vec<_>>();

        let block_hash = btc_rpc
            .get_block_hash(*safe_height)
            .await
            .map_err(|e| hyper_err!(RpcError, "Failed to get block hash: {}", e))?;
        let safe_chainwork = btc_rpc
            .get_chainwork(&block_hash)
            .await
            .map_err(|e| hyper_err!(RpcError, "Failed to get chainwork: {}", e))?;

        let retarget_height = safe_height - (safe_height % 2016);

        let retarget_block_hash = btc_rpc
            .get_block_hash(retarget_height)
            .await
            .map_err(|e| hyper_err!(RpcError, "Failed to get retarget block hash: {}", e))?;
        let retarget_block = btc_rpc
            .get_block(&retarget_block_hash)
            .await
            .map_err(|e| hyper_err!(RpcError, "Failed to get retarget block: {}", e))?;

        debug!(
            "Retarget block height: {}, reservation: {}",
            retarget_height, id
        );
        debug!(
            "Retarget block hash: {:?}, reservation: {}",
            retarget_block.block_hash().to_string(),
            id
        );

        debug!(
            "Confirmation Height: {}, reservation: {}",
            confirmation_height, id
        );

        active_reservations
            .with_lock(|reservations_guard| {
                reservations_guard.update_btc_reservation_final(
                    id.clone(),
                    *confirmation_height,
                    *block.block_hash().as_raw_hash().as_byte_array(),
                    *safe_height,
                    safe_chainwork,
                    blocks,
                    retarget_block,
                    retarget_height,
                );
            })
            .await;

        // add it the proof gen queue
        info!("Adding reservation: {} to proof generation queue", id);
        proof_gen_queue.add(proof_builder::ProofGenerationInput::new_reservation(
            id.clone(),
        ))?;
    }

    Ok(())
}

pub async fn find_block_height_from_time(
    rpc_url: &str,
    hours: u64,
    average_seconds_between_bitcoin_blocks: u64,
) -> Result<u64> {
    let rpc = BitcoinRpcClient::new(rpc_url);
    let time = Instant::now();
    let current_block_height = rpc
        .get_block_count()
        .await
        .map_err(|e| hyper_err!(RpcError, "Failed to get block count: {}", e))?;
    let current_block_hash = rpc
        .get_block_hash(current_block_height)
        .await
        .map_err(|e| hyper_err!(RpcError, "Failed to get block hash: {}", e))?;
    let current_block_timestamp = rpc
        .get_block(&current_block_hash)
        .await
        .map_err(|e| hyper_err!(RpcError, "Failed to get block: {}", e))?
        .header
        .time as u64;
    let target_timestamp = current_block_timestamp - hours * 3600;
    let blocks_per_hour = 3600 / average_seconds_between_bitcoin_blocks;
    let estimated_blocks_ago = hours * blocks_per_hour;
    let mut check_block = current_block_height.saturating_sub(estimated_blocks_ago);
    let mut previous_check_block = check_block + 1;

    while check_block > 0 && check_block != previous_check_block {
        previous_check_block = check_block;
        let block_hash = rpc
            .get_block_hash(check_block)
            .await
            .map_err(|e| hyper_err!(RpcError, "Failed to get block hash: {}", e))?;
        let block_timestamp = rpc
            .get_block(&block_hash)
            .await
            .map_err(|e| hyper_err!(RpcError, "Failed to get block: {}", e))?
            .header
            .time as u64;

        if block_timestamp <= target_timestamp {
            info!(
                "Found Bitcoin block height: {}, {:.2} hours from tip in {:?}",
                check_block,
                (current_block_timestamp - block_timestamp) as f64 / 3600 as f64,
                time.elapsed()
            );
            return Ok(check_block);
        }

        check_block = check_block.saturating_sub(blocks_per_hour);
    }

    info!(
        "Returning closest found block height: {}, search completed in {:?}",
        check_block,
        time.elapsed()
    );
    Ok(check_block)
}

async fn download_blocks(
    rpc: &BitcoinRpcClient,
    start_height: u64,
    end_height: u64,
    max_concurrent_requests: usize,
) -> Result<Vec<(u64, Block)>> {
    let heights_to_download = start_height..=end_height;

    info!(
        "Downloading bitcoin blocks: {} -> {}",
        start_height, end_height
    );

    let blocks_with_heights: Result<Vec<(u64, Block)>> = futures::stream::iter(heights_to_download)
        .map(|height| async move {
            let block_hash = rpc.get_block_hash(height).await.map_err(|e| {
                hyper_err!(
                    RpcError,
                    "Failed to get block hash for height {}: {}",
                    height,
                    e
                )
            })?;
            let block = rpc.get_block(&block_hash).await.map_err(|e| {
                hyper_err!(
                    RpcError,
                    "Failed to get block for hash {}: {}",
                    block_hash.to_hex_string(bitcoin::hex::Case::Lower),
                    e
                )
            })?;
            Ok((height, block))
        })
        .buffer_unordered(max_concurrent_requests)
        .try_collect()
        .await;

    let mut blocks_with_heights = blocks_with_heights?;
    blocks_with_heights.sort_by_key(|(height, _)| *height);

    Ok(blocks_with_heights)
}

// analyzes every btc block in the range [start_block_height, current_height] for reservation
// payments, once it's fully sync'd to the current tip, it will poll for new blocks every
// polling_interval seconds
pub async fn block_listener(
    btc_rpc: Arc<BitcoinRpcClient>,
    start_block_height: u64,
    polling_interval: u64,
    store: Arc<ThreadSafeStore>,
    proof_gen_queue: Arc<proof_builder::ProofGenerationQueue>,
    max_concurrent_requests: usize,
) -> Result<()> {
    let rpc = btc_rpc;
    let mut current_height = rpc
        .get_block_count()
        .await
        .map_err(|e| hyper_err!(RpcError, "Failed to get block count: {}", e))?;
    let mut analyzed_height = start_block_height.saturating_sub(1);
    let mut total_blocks_to_sync = current_height.saturating_sub(start_block_height);
    let mut fully_synced_logged = false;

    const PROVE_BLOCKS_INTERVAL: Duration = Duration::from_secs(1 * 3600); // 1 hour
    let mut last_prove_blocks_time = Instant::now() - PROVE_BLOCKS_INTERVAL;

    loop {
        if current_height > analyzed_height {
            let blocks_with_heights = download_blocks(
                &rpc,
                analyzed_height + 1,
                current_height,
                max_concurrent_requests,
            )
            .await?;

            for (height, block) in blocks_with_heights {
                analyzed_height = height;
                let current_timestamp = chrono::Utc::now().timestamp() as u64;

                store
                    .with_lock(|store| store.drop_expired_reservations(current_timestamp))
                    .await;

                let sift_start = Instant::now();
                analyze_block_for_payments(analyzed_height, &block, Arc::clone(&store)).await?;
                debug!(
                    "Analyzed bitcoin block: {} in {:?}",
                    analyzed_height,
                    sift_start.elapsed()
                );

                analyze_reservations_for_sufficient_confirmations(
                    analyzed_height,
                    &block,
                    Arc::clone(&store),
                    &rpc,
                    Arc::clone(&proof_gen_queue),
                )
                .await?;

                debug!(
                    "Analyzed bitcoin block: {} for confirmations in {:?}",
                    analyzed_height,
                    sift_start.elapsed()
                );

                let blocks_synced = analyzed_height - start_block_height + 1;
                let progress_percentage = ((blocks_synced as f64 / total_blocks_to_sync as f64)
                    * 100.0)
                    .clamp(0.0, 100.0);
                info!(
                    "Syncing bitcoin blocks: {:.2}% complete. Synced height: {}, Tip: {}",
                    progress_percentage, analyzed_height, current_height
                );
                fully_synced_logged = false;
            }
        } else {
            // We've caught up, check for new blocks
            let new_height = rpc
                .get_block_count()
                .await
                .map_err(|e| hyper_err!(RpcError, "Failed to get block count: {}", e))?;
            if new_height > current_height {
                // New blocks available, update and continue syncing
                current_height = new_height;
                total_blocks_to_sync = current_height - start_block_height + 1;
                info!(
                    "New bitcoin blocks found. Continuing sync to new tip: {}",
                    current_height
                );
                fully_synced_logged = false;
            } else if !fully_synced_logged {
                // We're fully synced, log only if not logged before
                info!("Fully synced. Waiting for new bitcoin blocks...");
                fully_synced_logged = true;
            }

            // Now that we're synced, check if we need to call proveBlocks
            let latest_contract_block_height = store
                .with_lock(|store| {
                    store
                        .safe_contract_block_hashes
                        .keys()
                        .max()
                        .cloned()
                        .unwrap_or(0)
                })
                .await;
            let latest_btc_block_height = rpc.get_block_count().await?;
            if latest_btc_block_height.saturating_sub(latest_contract_block_height)
                > CHECKPOINT_BLOCK_INTERVAL
            {
                let now = Instant::now();
                if now.duration_since(last_prove_blocks_time) >= PROVE_BLOCKS_INTERVAL {
                    info!(
                        "Calling proveBlocks at height {}",
                        latest_contract_block_height
                    );
                    let safe_height = latest_contract_block_height;
                    let mut confirmation_height = latest_btc_block_height;

                    // If the gap between the latest BTC block height and contract block height exceeds MAX_BLOCKS,
                    // we need to prove blocks in chunks of MAX_BLOCKS. For now, we'll prove only the most recent
                    // MAX_BLOCKS and rely on subsequent proveBlocks calls to catch up the remaining blocks.
                    if (MAX_BLOCKS as u64) < (confirmation_height - safe_height) {
                        confirmation_height = safe_height + MAX_BLOCKS as u64 - 1;
                    }

                    let blocks_with_heights = download_blocks(
                        &rpc,
                        safe_height,
                        confirmation_height,
                        max_concurrent_requests,
                    )
                    .await?;

                    info!("Downloaded {} blocks", blocks_with_heights.len());
                    let blocks: Vec<Block> = blocks_with_heights
                        .into_iter()
                        .map(|(_, block)| block)
                        .collect();

                    let block_hash = rpc
                        .get_block_hash(safe_height)
                        .await
                        .map_err(|e| hyper_err!(RpcError, "Failed to get block hash: {}", e))?;

                    let safe_chainwork = rpc
                        .get_chainwork(&block_hash)
                        .await
                        .map_err(|e| hyper_err!(RpcError, "Failed to get chainwork: {}", e))?;

                    let retarget_height = safe_height - (safe_height % 2016);

                    let retarget_block_hash =
                        rpc.get_block_hash(retarget_height).await.map_err(|e| {
                            hyper_err!(RpcError, "Failed to get retarget block hash: {}", e)
                        })?;
                    let retarget_block = rpc
                        .get_block(&retarget_block_hash)
                        .await
                        .map_err(|e| hyper_err!(RpcError, "Failed to get retarget block: {}", e))?;

                    info!(
                        "Contract database is out of sync by {} blocks. Proving blocks...",
                        latest_btc_block_height.saturating_sub(latest_contract_block_height)
                    );

                    proof_gen_queue.add(proof_builder::ProofGenerationInput::new_block_proof(
                        U256::from_be_slice(&safe_chainwork),
                        safe_height,
                        blocks,
                        retarget_block,
                        retarget_height,
                    ))?;

                    last_prove_blocks_time = now;
                }
            }

            // Sleep and try again
            tokio::time::sleep(tokio::time::Duration::from_secs(polling_interval)).await;
        }
    }
}
