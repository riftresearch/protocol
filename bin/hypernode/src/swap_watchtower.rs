use accumulators::mmr::leaf_count_to_mmr_size;
use std::str::FromStr;

use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider},
};
use bitcoin::{block::Version, consensus::Decodable, CompactTarget};
use bitcoin_data_engine::BitcoinDataEngine;
use bitcoin_light_client_core::{
    hasher::Keccak256Hasher, leaves::BlockLeaf, light_client::Header, ChainTransition, ProvenLeaf,
    VerifiedBlock,
};
use bitcoincore_rpc_async::{
    bitcoin::{block::Header as BlockHeader, hashes::Hash, Block, BlockHash, Txid},
    json::GetBlockVerboseOne,
    RpcApi,
};
use itertools::Itertools;
use rift_core::{
    giga::RiftProgramInput,
    order_hasher::SolidityHash,
    payments::{validate_bitcoin_payments, AggregateOrderHasher, OP_PUSHBYTES_32, OP_RETURN_CODE},
    spv::generate_bitcoin_txn_merkle_proof,
    OrderFillingTransaction,
};
use rift_indexer::engine::RiftIndexer;
use rift_sdk::{
    bitcoin_utils::{AsyncBitcoinClient, BitcoinClientExt},
    checkpoint_mmr::CheckpointedBlockTree,
    get_retarget_height_from_block_height,
    indexed_mmr::IndexedMMR,
    proof_generator::RiftProofGenerator,
    txn_builder::serialize_no_segwit,
};
use sol_bindings::{
    BlockProofParams, Order, RiftExchangeHarnessInstance, SubmitPaymentProofParams,
};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    sync::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        RwLockReadGuard,
    },
    task::JoinSet,
};
use tracing::{info, info_span, instrument, warn, Instrument};

use rift_sdk::txn_broadcast::{PreflightCheck, TransactionBroadcaster};

struct PendingPayment {
    paid_orders: Vec<Order>,
    committed_order_indices: Vec<usize>,
    payment_txid: Txid, //rely on bitcoin core for telling us how many confirmations this has?
    op_return_output_index: usize,
    group_confirmation_blocks: u32,
}

struct ConfirmedPayment {
    paid_orders: Vec<Order>,
    committed_order_indices: Vec<usize>,
    payment_txid: Txid,
    payment_block_leaf: BlockLeaf,
    order_filling_transaction_input: OrderFillingTransaction,
}

// const MAX_CONFIRMED_PAYMENT_RETRIES: u32 = 3;

pub struct SwapWatchtower;

impl SwapWatchtower {
    pub fn run(
        rift_indexer: Arc<RiftIndexer>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        evm_rpc: DynProvider,
        btc_rpc: Arc<AsyncBitcoinClient>,
        rift_exchange_address: Address,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        bitcoin_concurrency_limit: usize,
        proof_generator: Arc<RiftProofGenerator>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) {
        let (confirmed_swaps_tx, confirmed_swaps_rx) =
            tokio::sync::mpsc::unbounded_channel::<Vec<ConfirmedPayment>>();

        let evm_rpc_clone = evm_rpc.clone();
        let btc_rpc_clone = btc_rpc.clone();
        let rift_indexer_clone = rift_indexer.clone();
        let bitcoin_data_engine_clone = bitcoin_data_engine.clone();

        join_set.spawn(
            async move {
                Self::search_for_swap_payments(
                    evm_rpc_clone,
                    btc_rpc_clone,
                    rift_indexer_clone,
                    bitcoin_data_engine_clone,
                    bitcoin_concurrency_limit,
                    confirmed_swaps_tx,
                )
                .await
            }
            .instrument(info_span!("Bitcoin Payment Watchtower")),
        );

        let btc_rpc_clone = btc_rpc;
        let evm_rpc_clone = evm_rpc;
        let transaction_broadcaster_clone = transaction_broadcaster;
        let rift_indexer_clone = rift_indexer;
        let bitcoin_data_engine_clone = bitcoin_data_engine;
        let proof_generator_clone = proof_generator;
        join_set.spawn(
            async move {
                Self::finalize_confirmed_swaps(
                    confirmed_swaps_rx,
                    btc_rpc_clone,
                    bitcoin_data_engine_clone,
                    rift_indexer_clone,
                    bitcoin_concurrency_limit,
                    proof_generator_clone,
                    rift_exchange_address,
                    evm_rpc_clone,
                    transaction_broadcaster_clone,
                )
                .await
            }
            .instrument(info_span!("Confirmed Swaps Finalizer")),
        );
    }

    // called by search_for_swaps thread
    async fn search_for_swap_payments(
        evm_rpc: DynProvider,
        btc_rpc: Arc<AsyncBitcoinClient>,
        rift_indexer: Arc<RiftIndexer>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        bitcoin_concurrency_limit: usize,
        confirmed_swaps_tx: UnboundedSender<Vec<ConfirmedPayment>>,
    ) -> eyre::Result<()> {
        info!("Starting swap search");
        let mut block_subscribtion = bitcoin_data_engine.subscribe_to_new_blocks();
        info!("Subscribed to new bitcoin blocks");

        let (start_search_bitcoin_block_number, end_search_bitcoin_block_number) =
            compute_block_search_range(
                evm_rpc,
                btc_rpc.clone(),
                rift_indexer.clone(),
                bitcoin_data_engine.clone(),
            )
            .await?;

        info!(
            message = "Searching for swaps from block {} to {}",
            start_search_bitcoin_block_number, end_search_bitcoin_block_number
        );

        // download block leaves from start_search_bitcoin_block_number to end_search_bitcoin_block_number
        let mut block_leaves = btc_rpc
            .get_leaves_from_block_range(
                start_search_bitcoin_block_number,
                end_search_bitcoin_block_number,
                bitcoin_concurrency_limit,
                None,
            )
            .await?;
        let mut first_run = true;

        // TODO: We need an eviction strategy for pending swaps
        // Evict any pending swaps that have an expired deposit vault
        let mut pending_payments = Vec::new();

        loop {
            // Collect all available new blocks from the subscription
            if !first_run {
                info!(
                    message = "Waiting for new block",
                    operation = "block_subscription"
                );
                // After the first run, await a new block before continuing
                let new_leaf = block_subscribtion.recv().await?;
                info!(
                    message = "New block received",
                    operation = "block_subscription"
                );
                block_leaves.push(new_leaf);
            }

            // Then collect any additional blocks that have arrived
            loop {
                match block_subscribtion.try_recv() {
                    Ok(new_leaf) => block_leaves.push(new_leaf),
                    Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                    Err(e) => return Err(eyre::eyre!("Block subscription channel error: {}", e)),
                }
            }
            info!(
                message = "Analyzing blocks for swaps",
                block_count = block_leaves.len(),
                operation = "block_analysis"
            );

            if first_run {
                first_run = false;
            }

            if block_leaves.is_empty() {
                continue;
            }

            let full_blocks = btc_rpc
                .get_blocks_from_leaves(&block_leaves, bitcoin_concurrency_limit)
                .await?;

            pending_payments
                .extend(find_new_swaps_in_blocks(rift_indexer.clone(), &full_blocks).await?);

            let confirmed_payments = find_pending_swaps_with_sufficient_confirmations(
                btc_rpc.clone(),
                &mut pending_payments,
            )
            .await?;

            if !confirmed_payments.is_empty() {
                info!("Found {} confirmed payments", confirmed_payments.len());
                confirmed_swaps_tx.send(confirmed_payments)?;
            } else {
                info!(
                    message = "No confirmed swaps found",
                    operation = "confirmed_swaps"
                );
            }

            // clear block leaves before looping back
            block_leaves.clear();
        }
    }

    async fn finalize_confirmed_swaps(
        mut confirmed_swaps_rx: UnboundedReceiver<Vec<ConfirmedPayment>>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        rift_indexer: Arc<RiftIndexer>,
        bitcoin_concurrency_limit: usize,
        proof_generator: Arc<RiftProofGenerator>,
        evm_address: Address,
        evm_rpc: DynProvider,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
    ) -> eyre::Result<()> {
        let rift_exchange = RiftExchangeHarnessInstance::new(evm_address, evm_rpc);
        loop {
            let mut confirmed_swaps = confirmed_swaps_rx.recv().await.ok_or_else(|| {
                eyre::eyre!("Confirmed swaps channel receiver unexpectedly closed")
            })?;

            loop {
                // drain the channel of any additional confirmed swaps to handle in one batch
                match confirmed_swaps_rx.try_recv() {
                    Ok(new_confirmed_swaps) => {
                        confirmed_swaps.extend(new_confirmed_swaps);
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(e) => return Err(eyre::eyre!("Confirmed swaps channel error: {}", e)),
                }
            }

            // TODO: Some validation that the TXNS are still in the longest chain and then pushing them back to the
            // pending swaps queue if they do not would be ideal
            // Assume for now that if the txns are here they're part of the longest chain
            // 1. Determine what the state of the onchain light client is (current tip)
            // 2. If it's equal to the locally stored chain, do nothing

            // lock both the light client and bitcoin core mmrs while we finalize the swaps
            let light_client_mmr = rift_indexer.checkpointed_block_tree.read().await;
            let bitcoin_mmr = bitcoin_data_engine.indexed_mmr.read().await;
            let btc_light_client_root = light_client_mmr.get_root().await?;
            let btc_local_root = bitcoin_mmr.get_root().await?;
            info!(message = "Starting finalize_confirmed_swaps");

            let mut light_client_update = false;
            let mut rift_program_input_builder = RiftProgramInput::builder();
            if btc_light_client_root != btc_local_root {
                let light_client_span =
                    info_span!("light_client_update", operation = "build_transition");
                let _enter = light_client_span.enter();

                info!(message = "Building light client update");
                let chain_transition = build_chain_transition_for_light_client_update(
                    btc_rpc.clone(),
                    &bitcoin_mmr,
                    &light_client_mmr,
                    bitcoin_concurrency_limit,
                )
                .await?;

                info!("chain transition: {:#?}", chain_transition);

                info!(message = "Light client update built");
                light_client_update = true;
                rift_program_input_builder =
                    rift_program_input_builder.light_client_input(chain_transition);
                rift_program_input_builder =
                    rift_program_input_builder.proof_type(rift_core::giga::RustProofType::Combined);
            } else {
                rift_program_input_builder =
                    rift_program_input_builder.proof_type(rift_core::giga::RustProofType::SwapOnly);
            }
            // Build swap params, also building MMR proofs for each confirmed swap
            // TODO: We could start building these params while the proof is generating
            let mut swap_params = Vec::new();
            for swap in &confirmed_swaps {
                let proof = bitcoin_mmr
                    .get_circuit_proof(swap.payment_block_leaf.height as usize, None)
                    .await?;

                for order_index in &swap.committed_order_indices {
                    let order = swap.paid_orders[*order_index].clone();
                    swap_params.push(SubmitPaymentProofParams {
                        paymentBitcoinTxid: swap.payment_txid.as_raw_hash().to_byte_array().into(),
                        order,
                        paymentBitcoinBlockLeaf: swap.payment_block_leaf.into(),
                        paymentBitcoinBlockSiblings: proof
                            .siblings
                            .iter()
                            .map(From::from)
                            .collect(),
                        paymentBitcoinBlockPeaks: proof.peaks.iter().map(From::from).collect(),
                    });
                }
            }

            // free the locks, we no longer need them
            drop(light_client_mmr);
            drop(bitcoin_mmr);

            rift_program_input_builder = rift_program_input_builder
                .order_filling_transaction_input(
                    confirmed_swaps
                        .iter()
                        .map(|swap| swap.order_filling_transaction_input.clone())
                        .collect(),
                );

            let rift_program_input = rift_program_input_builder
                .build()
                .map_err(|e| eyre::eyre!("Failed to build rift program input: {}", e))?;

            let (public_values_simulated, auxiliary_data) = rift_program_input
                .get_auxiliary_light_client_data()
                .map_err(|e| eyre::eyre!("Failed to get auxiliary light client data: {}", e))?;

            let proof = proof_generator
                .prove(&rift_program_input)
                .await
                .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;

            info!("Proof generated: {:?}", proof);

            let block_proof_params = if light_client_update {
                Some(BlockProofParams {
                    priorMmrRoot: public_values_simulated.priorMmrRoot,
                    newMmrRoot: public_values_simulated.newMmrRoot,
                    tipBlockLeaf: public_values_simulated.tipBlockLeaf,
                    compressedBlockLeaves: auxiliary_data.compressed_leaves.into(),
                })
            } else {
                None
            };

            let proof_bytes = match proof.proof {
                Some(proof) => proof.bytes(),
                None => {
                    warn!("No proof used for light client update, assuming mock proof");
                    vec![]
                }
            };

            let (transaction_request, calldata) = if let Some(block_proof_params) =
                block_proof_params
            {
                let call = rift_exchange.submitPaymentProofs(
                    swap_params,
                    block_proof_params,
                    proof_bytes.into(),
                );
                let calldata = call.calldata().to_owned();
                let transaction_request = call.into_transaction_request();
                (transaction_request, calldata)
            } else {
                let call = rift_exchange.submitPaymentProofsOnly(swap_params, proof_bytes.into());
                let calldata = call.calldata().to_owned();
                let transaction_request = call.into_transaction_request();
                (transaction_request, calldata)
            };

            let txn = transaction_broadcaster
                .broadcast_transaction(calldata, transaction_request, PreflightCheck::Simulate)
                .await?;
            info!("Submitted swap proof with txn exeuction result: {:?}", txn);
            // TODO: Handle txn failure cases, and retry logic
        }
    }
}

// Computes how far back in terms of bitcoin blocks to search for swaps based on the oldest active deposit
async fn compute_block_search_range(
    evm_rpc: DynProvider,
    btc_rpc: Arc<AsyncBitcoinClient>,
    rift_indexer: Arc<RiftIndexer>,
    bitcoin_data_engine: Arc<BitcoinDataEngine>,
) -> eyre::Result<(u32, u32)> {
    let current_evm_timestamp = evm_rpc
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await?
        .ok_or_else(|| eyre::eyre!("Failed to get latest block"))?
        .header
        .timestamp;

    let current_btc_tip = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_count()
        .await?
        - 1;

    let oldest_active_deposit = rift_indexer
        .get_oldest_active_order(current_evm_timestamp)
        .await?;

    let end_search_bitcoin_block_number = current_btc_tip as u32;

    let start_search_bitcoin_block_number =
        if let Some(oldest_active_deposit) = oldest_active_deposit {
            info!(
                message = "Oldest active deposit",
                deposit_timestamp = oldest_active_deposit.order.timestamp,
                operation = "compute_block_search_range"
            );
            btc_rpc
                .find_oldest_block_before_timestamp(oldest_active_deposit.order.timestamp)
                .await?
        } else {
            info!(
                "No active deposit found, beginning search from the current tip {}",
                end_search_bitcoin_block_number
            );
            // No active deposit found, so we can start searching from the current tip
            end_search_bitcoin_block_number
        };

    Ok((
        start_search_bitcoin_block_number,
        end_search_bitcoin_block_number,
    ))
}

#[instrument(level = "info", skip(rift_indexer, blocks))]
async fn find_new_swaps_in_blocks(
    rift_indexer: Arc<RiftIndexer>,
    blocks: &[Block],
) -> eyre::Result<Vec<PendingPayment>> {
    /*
    Rift Transaction Filter [function]
    given a block
        - if a txn has an `output` with `OP_RETURN` followed
          by 32 bytes this is potentially* a Rift transaction.
        - if above true, query Data Engine with the extracted
          OP_RETURN data, if a response is found this is almost
          certainly a Rift TXN.
        - if above true, check if the payment details specified
          in the db query align with what is in the btc txn. If
          it does, this is *definitely* a Rift txn.
        - if the above is true, store the TXN in a queue waiting
          for sufficient confirmations.
     */
    let mut pending_payments = Vec::new();
    for block in blocks {
        for tx in block.txdata.clone() {
            // check if the tx is a swap
            let txid = tx.compute_txid();
            // TODO: Handle each tx as a potentially OrderFillingTransaction
            let mut potential_payment_outputs = Vec::new();
            // iterate over the outputs of the tx until we find an OP_RETURN output
            // then check if the OP_RETURN data is a valid aggregate order hash
            for (current_output_index, output) in tx.output.clone().iter().enumerate() {
                potential_payment_outputs.push(output);
                if current_output_index == 0 {
                    // OP_RETURN is never the first output in a rift payment bitcoin transaction
                    continue;
                }
                if output.script_pubkey.len() != 34 {
                    continue;
                }
                let script_pubkey_bytes = output.script_pubkey.as_bytes();
                if script_pubkey_bytes[0] != OP_RETURN_CODE {
                    continue;
                }
                if script_pubkey_bytes[1] != OP_PUSHBYTES_32 {
                    continue;
                }
                let potential_aggregate_order_hash: [u8; 32] =
                    script_pubkey_bytes[2..34].try_into()?;

                info!(
                    message = "Found OP_RETURN output",
                    op_return_output_index = current_output_index,
                    operation = "find_new_swaps_in_blocks",
                    aggregate_order_hash = hex::encode(potential_aggregate_order_hash)
                );
                // remove the OP_RETURN output from the list of potential payment outputs
                potential_payment_outputs.pop();
                /*
                   At this point, we potentially have a match
                   we now look up in the DB if there are orders
                   that match these params.
                   Note that we MUST break if a check fails beyond this point
                */
                info!(
                    message = "Searching for matching orders",
                    operation = "find_new_swaps_in_blocks",
                    payment_outputs = potential_payment_outputs.len(),
                    aggregate_order_hash = hex::encode(potential_aggregate_order_hash)
                );

                let script_pub_key_amount_pairs = potential_payment_outputs
                    .iter()
                    .map(|output| (output.script_pubkey.as_bytes(), output.value.to_sat()))
                    .collect::<Vec<_>>();

                let nested_potential_orders = rift_indexer
                    .get_live_orders_by_script_and_amounts(&script_pub_key_amount_pairs)
                    .await?;

                // Couldn't find live orders that matched all payments
                if nested_potential_orders.is_none() {
                    info!(
                        message = "No matching orders found in the DB",
                        operation = "find_new_swaps_in_blocks",
                        script_pub_key_amount_pairs = format!(
                            "{:?}",
                            script_pub_key_amount_pairs
                                .iter()
                                .map(|(script, amt)| (hex::encode(script), amt))
                                .collect::<Vec<_>>()
                        ),
                        aggregate_order_hash = hex::encode(potential_aggregate_order_hash)
                    );
                    break;
                }

                // get rid of the ChainAwareOrder wrapper struct
                let nested_potential_orders = nested_potential_orders
                    .unwrap()
                    .iter()
                    .map(|chain_orders| {
                        chain_orders
                            .iter()
                            .map(|chain_order| chain_order.order.clone())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let matched_orders = search_for_matching_aggregate_order_hash(
                    &nested_potential_orders,
                    potential_aggregate_order_hash,
                );

                if matched_orders.is_none() {
                    info!(
                        message = "No matching order paths found",
                        operation = "find_new_swaps_in_blocks",
                        aggregate_order_hash = hex::encode(potential_aggregate_order_hash)
                    );
                    break;
                }

                // At this point, we have a list of orders that match the aggregate order hash
                let matched_orders = matched_orders.unwrap();

                let serialized = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&tx);
                let mut reader = serialized.as_slice();
                let canon_bitcoin_tx = bitcoin::Transaction::consensus_decode(&mut reader)
                    .map_err(|e| eyre::eyre!("Failed to deserialize transaction: {}", e))?;

                let tx_data_no_segwit = serialize_no_segwit(&canon_bitcoin_tx)?;

                let payment_validation = validate_bitcoin_payments(
                    &tx_data_no_segwit,
                    &matched_orders,
                    current_output_index,
                );
                if payment_validation.is_err() {
                    info!(
                        "Invalid payment tx for order indices {} with bitcoin txid: {}, skipping...",
                        matched_orders
                            .iter()
                            .map(|order| order.index)
                            .collect::<Vec<_>>()
                            .iter().join(","),
                        txid
                    );
                    continue;
                }

                info!(
                    "Found a potential fill transaction for order indices {} with bitcoin txid: {}",
                    matched_orders
                        .iter()
                        .map(|order| order.index)
                        .collect::<Vec<_>>()
                        .iter()
                        .join(","),
                    txid
                );

                // We can only submit payments for orders that have the same number of confirmations
                let confirmation_groups = group_by_confirmation_blocks(&matched_orders);
                for (confirmation_blocks, order_indices) in confirmation_groups {
                    pending_payments.push(PendingPayment {
                        paid_orders: matched_orders.clone(),
                        committed_order_indices: order_indices,
                        payment_txid: txid,
                        op_return_output_index: current_output_index,
                        group_confirmation_blocks: confirmation_blocks,
                    });
                }
            }
        }
    }

    Ok(pending_payments)
}

/// Split orders into groups of their indices, bucketed by `confirmation_blocks`.
///
/// Example:
/// ```
/// let orders = vec![
///     Order { confirmation_blocks: 1 },
///     Order { confirmation_blocks: 2 },
///     Order { confirmation_blocks: 3 },
///     Order { confirmation_blocks: 2 },
///     Order { confirmation_blocks: 2 },
///     Order { confirmation_blocks: 1 },
/// ];
/// let groups = split_by_confirmation_blocks(&orders);
/// // `groups` now contains (in any order): vec![vec![0, 5], vec![1, 3, 4], vec![2]]
/// ```
pub fn group_by_confirmation_blocks(orders: &[Order]) -> HashMap<u32, Vec<usize>> {
    // 1. Fill the buckets in a single pass.
    let mut buckets: HashMap<u32, Vec<usize>> = HashMap::with_capacity(orders.len());
    for (idx, order) in orders.iter().enumerate() {
        buckets
            .entry(order.confirmationBlocks.into())
            .or_default()
            .push(idx);
    }

    buckets
}

// CPU heavy function that searches for a matching aggregate order hash
fn search_for_matching_aggregate_order_hash(
    nested_orders: &[Vec<Order>],
    aggregate_order_hash: [u8; 32],
) -> Option<Vec<Order>> {
    // Precompute the order hash for each order at each level
    // Use a hashmap to store the order hash as the key and the order as the value
    let mut order_hash_to_order = HashMap::new();
    let mut nested_order_hashes = Vec::new();
    for order_list in nested_orders {
        let mut order_hashes = Vec::new();
        for order in order_list {
            let order_hash = order.hash();
            order_hash_to_order.insert(order_hash, order);
            order_hashes.push(order_hash);
        }
        nested_order_hashes.push(order_hashes);
    }
    // Compute the cartesian product to determine all the various order hash permutations
    // and check if any of them match the aggregate order hash

    let matched_hash_list = nested_order_hashes
        .iter()
        .map(|x| x.iter())
        .multi_cartesian_product()
        .find(|order_hash_permutation| {
            aggregate_order_hash == order_hash_permutation.compute_aggregate_hash()
        });

    matched_hash_list.map(|matched_hash_list| {
        matched_hash_list
            .iter()
            .map(|order_hash| order_hash_to_order[*order_hash].clone())
            .collect::<Vec<_>>()
    })
}

#[instrument(level = "info", skip(btc_rpc, pending_swaps))]
async fn find_pending_swaps_with_sufficient_confirmations(
    btc_rpc: Arc<AsyncBitcoinClient>,
    pending_swaps: &mut Vec<PendingPayment>,
) -> eyre::Result<Vec<ConfirmedPayment>> {
    let mut confirmed_swaps = Vec::new();
    let mut i = 0;

    while i < pending_swaps.len() {
        // specifically don't pass a block hash here in the case that a reorg placed the txn
        // in a different block
        let txn_result = btc_rpc
            .get_raw_transaction_verbose(&pending_swaps[i].payment_txid)
            .await?;

        // Confirmations should always be set here b/c we're setting the verbose flag by calling
        // get_raw_transaction_info
        let confirmations = txn_result
            .confirmations
            .expect("Confirmations wasn't returned");

        if confirmations >= pending_swaps[i].group_confirmation_blocks as u64 {
            let pending_swap = pending_swaps.remove(i);

            // (getblock w/ verbosity 1 is light bandwidth wise compared to full block download)
            let block_hash_hex = txn_result
                .block_hash
                .ok_or_else(|| eyre::eyre!("Transaction has no block hash"))?;
            let block_hash = bitcoincore_rpc_async::bitcoin::BlockHash::from_str(&block_hash_hex)
                .map_err(|e| eyre::eyre!("Failed to parse block hash: {}", e))?;
            let block_info = btc_rpc.get_block_verbose_one(&block_hash).await?;
            let (block_leaf, block_header) =
                get_leaf_and_block_header_from_block_info(&block_info)?;

            let txn_hex_bytes = hex::decode(&txn_result.hex)
                .map_err(|e| eyre::eyre!("Failed to decode transaction hex: {}", e))?;
            let txn: bitcoin::Transaction = bitcoin::consensus::deserialize(&txn_hex_bytes)
                .map_err(|e| eyre::eyre!("Failed to deserialize transaction: {}", e))?;
            let mut tx_hash: [u8; 32] = hex::decode(&txn_result.txid)
                .map_err(|e| eyre::eyre!("Failed to decode txid hex: {}", e))?
                .try_into()
                .map_err(|e| eyre::eyre!("Txid is not 32 bytes: {:?}", e))?;
            tx_hash.reverse();

            let block_header: Header =
                bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&block_header)
                    .try_into()
                    .map_err(|e| eyre::eyre!("Failed to serialize block header: {}", e))?;

            let (merkle_proof, _block_merkle_root) = generate_bitcoin_txn_merkle_proof(
                &block_info
                    .tx
                    .iter()
                    .map(|txid_hex| {
                        let bytes = hex::decode(txid_hex).expect("Invalid txid hex");
                        let mut array = [0u8; 32];
                        array.copy_from_slice(&bytes);
                        array.reverse();
                        array
                    })
                    .collect::<Vec<[u8; 32]>>(),
                tx_hash,
            )
            .map_err(|e| eyre::eyre!("Failed to generate merkle proof: {}", e))?;

            let rift_transaction_input = OrderFillingTransaction {
                txn: serialize_no_segwit(&txn).unwrap(),
                paid_orders: pending_swap.paid_orders.clone(),
                order_indices: pending_swap.committed_order_indices.clone(),
                op_return_output_index: pending_swap.op_return_output_index,
                block_header,
                txn_merkle_proof: merkle_proof,
            };
            // This swap is confirmed, move it to confirmed_swaps
            confirmed_swaps.push(ConfirmedPayment {
                paid_orders: pending_swap.paid_orders.clone(),
                committed_order_indices: pending_swap.committed_order_indices.clone(),
                payment_txid: pending_swap.payment_txid,
                payment_block_leaf: block_leaf,
                order_filling_transaction_input: rift_transaction_input,
            });
            // Don't increment i since we've shifted the vector
        } else {
            // This swap is still pending
            i += 1;
        }
    }

    Ok(confirmed_swaps)
}

fn get_leaf_and_block_header_from_block_info(
    block: &GetBlockVerboseOne,
) -> eyre::Result<(BlockLeaf, BlockHeader)> {
    let chainwork: [u8; 32] = hex::decode(&block.chain_work)
        .map_err(|e| eyre::eyre!("Failed to decode chainwork: {}", e))?
        .try_into()
        .map_err(|e| eyre::eyre!("Chainwork is not 32 bytes: {:?}", e))?;

    let explorer_block_hash: [u8; 32] = hex::decode(&block.hash)
        .map_err(|e| eyre::eyre!("Failed to decode block hash: {}", e))?
        .try_into()
        .map_err(|e| eyre::eyre!("Block hash is not 32 bytes: {:?}", e))?;
    let leaf = BlockLeaf::new(explorer_block_hash, block.height as u32, chainwork);

    // Parse `bits` from hex:
    let parsed_bits = u32::from_str_radix(&block.bits, 16)
        .map_err(|e| eyre::eyre!("Block {} has invalid bits: {}", block.hash, e))?;

    let prev_blockhash = if let Some(ref prev_hash_hex) = block.previous_block_hash {
        let mut bytes: [u8; 32] = hex::decode(prev_hash_hex)
            .map_err(|e| eyre::eyre!("Failed to decode previous block hash: {}", e))?
            .try_into()
            .map_err(|e| eyre::eyre!("Previous block hash is not 32 bytes: {:?}", e))?;
        bytes.reverse(); // Convert from little-endian to internal format
        bitcoincore_rpc_async::bitcoin::BlockHash::from_byte_array(bytes)
    } else {
        return Err(eyre::eyre!(
            "Block {} has no previous block hash",
            block.hash
        ));
    };

    let mut merkle_root: [u8; 32] = hex::decode(&block.merkle_root)
        .map_err(|e| eyre::eyre!("Failed to decode merkle root: {}", e))?
        .try_into()
        .map_err(|e| eyre::eyre!("Merkle root is not 32 bytes: {:?}", e))?;
    merkle_root.reverse(); // Convert from little-endian to internal format

    let block_header = BlockHeader {
        version: Version::from_consensus(block.version),
        prev_blockhash,
        merkle_root: bitcoincore_rpc_async::bitcoin::hash_types::TxMerkleNode::from_byte_array(
            merkle_root,
        ),
        time: block.time as u32,
        bits: CompactTarget::from_consensus(parsed_bits),
        nonce: block.nonce as u32,
    };

    assert_eq!(
        block.hash,
        block_header.block_hash().to_string(),
        "Block hash mismatch: {} != {}",
        block.hash,
        block_header.block_hash()
    );

    Ok((leaf, block_header))
}

/// Builds a chain transition for updating the light client state.
///
/// This function creates a ChainTransition that represents the progression from
/// the current state of the contract's light client to a new state that includes
/// more recent Bitcoin blocks.
///
/// # Arguments
///
/// * `bitcoin_data_engine` - The Bitcoin data engine that contains the latest chain data
/// * `rift_indexer` - The contract data engine that contains the current on-chain state
///
/// # Returns
///
/// A Result containing the ChainTransition if successful, or an error otherwise
#[instrument(level = "info", skip(btc_rpc, bitcoin_mmr, light_client_mmr))]
pub async fn build_chain_transition_for_light_client_update<'a>(
    btc_rpc: Arc<AsyncBitcoinClient>,
    bitcoin_mmr: &RwLockReadGuard<'a, IndexedMMR<Keccak256Hasher>>,
    light_client_mmr: &RwLockReadGuard<'a, CheckpointedBlockTree<Keccak256Hasher>>,
    bitcoin_concurrency_limit: usize,
) -> eyre::Result<ChainTransition> {
    info!("Building chain transition");
    // Find a "parent" leaf that both the light client and bitcoin core know about and agree
    // about being in the longest chain
    // Also get the current tip, the best leaf the light client knows about
    let (
        bitcoin_tip_height,
        current_mmr_root,
        current_mmr_bagged_peak,
        parent_leaf_peaks,
        current_tip_with_proof,
        parent_with_proof,
        parent_retarget_with_proof,
        disposed_leaves,
    ) = {
        // lock both the light client and bitcoin core mmrs while we search
        // b/c all lookups happen on local databases: this should be fast

        let current_mmr_root = light_client_mmr.get_root().await?;
        let current_mmr_bagged_peak = light_client_mmr.get_bagged_peak().await?;

        let current_tip_leaf_index = light_client_mmr.get_leaf_count().await? - 1;
        let current_tip_leaf = light_client_mmr
            .get_leaf_by_leaf_index(current_tip_leaf_index)
            .await?
            .ok_or_else(|| {
                eyre::eyre!(
                    "Failed to get current leaf at index {}",
                    current_tip_leaf_index
                )
            })?;
        // iterate to find the parent leaf
        let mut parent_leaf_index = current_tip_leaf_index;
        let mut parent_leaf = current_tip_leaf;
        // leaves to remove from the light client (assumed that the light client is always a subset of the bitcoin data engine)
        let mut disposed_leaves = Vec::new();
        loop {
            // query bitcoin data engine for parent leaf
            let parent_leaf_hash = parent_leaf.hash::<Keccak256Hasher>();
            let potential_parent = bitcoin_mmr.get_leaf_by_leaf_hash(&parent_leaf_hash).await?;
            if potential_parent.is_some() {
                break;
            }
            // if we're here, the parent leaf is not in the bitcoin data engine, so we need to remove it from the light client
            disposed_leaves.push(parent_leaf);
            parent_leaf_index -= 1;
            if parent_leaf_index == 0 {
                return Err(eyre::eyre!("Failed to find parent leaf"));
            }
            // query light client for parent leaf, should always succeed
            parent_leaf = light_client_mmr
                .get_leaf_by_leaf_index(parent_leaf_index)
                .await?
                .ok_or_else(|| {
                    eyre::eyre!("Failed to get parent leaf at index {}", parent_leaf_index)
                })?;
            info!(
                "Could not find parent leaf {} in bitcoin data engine, checking next parent...",
                hex::encode(parent_leaf_hash)
            );
        }
        info!("Parent leaf index: {}", parent_leaf_index);
        info!(
            "Getting peaks for element count: {}",
            leaf_count_to_mmr_size(parent_leaf_index + 1)
        );

        // get the peaks of the light client mmr as if the parent leaf was the tip of the MMR
        let parent_leaf_peaks = light_client_mmr
            .get_peaks(Some(leaf_count_to_mmr_size(parent_leaf_index + 1)))
            .await?;

        println!("Parent leaf peaks: {:?}", parent_leaf_peaks);

        let parent_retarget_height = get_retarget_height_from_block_height(parent_leaf.height);
        let parent_retarget_leaf = bitcoin_mmr
            .get_leaf_by_leaf_index(parent_retarget_height as usize)
            .await?
            .ok_or_else(|| {
                eyre::eyre!(
                    "Failed to get parent retarget leaf at index {}",
                    parent_retarget_height
                )
            })?;

        let parent_retarget_inclusion_proof = light_client_mmr
            .get_circuit_proof(parent_retarget_height as usize, None)
            .await?;

        let parent_inclusion_proof = light_client_mmr
            .get_circuit_proof(parent_leaf_index, None)
            .await?;

        let current_tip_proof = light_client_mmr
            .get_circuit_proof(current_tip_leaf_index, None)
            .await?;

        let parent_retarget_with_proof = ProvenLeaf {
            leaf: parent_retarget_leaf,
            proof: parent_retarget_inclusion_proof,
        };

        let parent_with_proof = ProvenLeaf {
            leaf: parent_leaf,
            proof: parent_inclusion_proof,
        };

        let current_tip_with_proof = ProvenLeaf {
            leaf: current_tip_leaf,
            proof: current_tip_proof,
        };

        let bitcoin_tip_height = bitcoin_mmr.get_leaf_count().await? - 1;

        (
            bitcoin_tip_height,
            current_mmr_root,
            current_mmr_bagged_peak,
            parent_leaf_peaks,
            current_tip_with_proof,
            parent_with_proof,
            parent_retarget_with_proof,
            disposed_leaves,
        )
    };

    info!(message = "Building parent header");
    let parent_header: Header = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(
        &btc_rpc
            .get_block_header(&BlockHash::from_slice(
                &parent_with_proof.leaf.natural_block_hash(),
            )?)
            .await?,
    )
    .try_into()
    .map_err(|e| eyre::eyre!("Failed to serialize parent header: {}", e))?;

    let parent_retarget_header: Header =
        bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(
            &btc_rpc
                .get_block_header(&BlockHash::from_slice(
                    &parent_retarget_with_proof.leaf.natural_block_hash(),
                )?)
                .await?,
        )
        .try_into()
        .map_err(|e| eyre::eyre!("Failed to serialize parent retarget header: {}", e))?;

    // finally get the new headers from bitcoin data engine
    let new_headers = if bitcoin_tip_height != (parent_with_proof.leaf.height as usize + 1) {
        btc_rpc
            .get_headers_from_block_range(
                parent_with_proof.leaf.height + 1,
                bitcoin_tip_height as u32,
                bitcoin_concurrency_limit,
                None,
            )
            .await?
            .iter()
            .map(|header| {
                bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(header)
                    .try_into()
                    .map_err(|e| eyre::eyre!("Failed to serialize header: {}", e))
            })
            .collect::<Result<Vec<Header>, _>>()?
    } else {
        return Err(eyre::eyre!("No new headers to update light client"));
    };

    // Build the ChainTransition
    Ok(ChainTransition {
        current_mmr_root,
        current_mmr_bagged_peak,

        parent: VerifiedBlock {
            header: parent_header,
            mmr_data: parent_with_proof,
        },
        parent_retarget: VerifiedBlock {
            header: parent_retarget_header,
            mmr_data: parent_retarget_with_proof,
        },
        current_tip: current_tip_with_proof,
        parent_leaf_peaks,
        disposed_leaf_hashes: disposed_leaves
            .iter()
            .map(|leaf| leaf.hash::<Keccak256Hasher>())
            .collect(),
        new_headers,
    })
}
