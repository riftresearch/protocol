use accumulators::mmr::map_leaf_index_to_element_index;
use alloy::{
    eips::eip7251::ConsolidationRequest, primitives::Address, providers::Provider,
    pubsub::PubSubFrontend, sol_types::SolValue,
};
use bitcoin::consensus::Decodable;
use bitcoin_data_engine::BitcoinDataEngine;
use bitcoin_light_client_core::{
    hasher::Keccak256Hasher, leaves::BlockLeaf, light_client::Header, ChainTransition, ProvenLeaf,
    VerifiedBlock,
};
use bitcoincore_rpc_async::{
    bitcoin::{hashes::Hash, Block, BlockHash, Txid},
    RpcApi,
};
use data_engine::{engine::DataEngine, models::ChainAwareDeposit};
use rift_core::payments::{validate_bitcoin_payment, OP_PUSHBYTES_32, OP_RETURN_CODE};
use rift_sdk::{
    bitcoin_utils::{AsyncBitcoinClient, BitcoinClientExt},
    get_retarget_height_from_block_height,
    txn_builder::serialize_no_segwit,
};
use sol_bindings::Types::DepositVault;
use std::sync::Arc;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};
use tracing::info;

struct PendingSwap {
    chain_aware_deposit: ChainAwareDeposit,
    payment_txid: Txid, //rely on bitcoin core for telling us how many confirmations this has?
}

struct ConfirmedSwap {
    chain_aware_deposit: ChainAwareDeposit,
    payment_txid: Txid,
    payment_block_leaf: BlockLeaf,
}

struct SwapWatchtower {
    contract_data_engine: Arc<DataEngine>,
    bitcoin_data_engine: Arc<BitcoinDataEngine>,
    evm_rpc: Arc<dyn Provider<PubSubFrontend>>,
    btc_rpc: Arc<AsyncBitcoinClient>,
    rift_exchange_address: Address,
    searcher_handle: JoinHandle<eyre::Result<()>>,
    finalizer_handle: JoinHandle<eyre::Result<()>>,
    // State
}

impl SwapWatchtower {
    pub fn new(
        contract_data_engine: Arc<DataEngine>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        evm_rpc: Arc<dyn Provider<PubSubFrontend>>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        rift_exchange_address: Address,
        bitcoin_concurrency_limit: usize,
    ) -> Self {
        let (confirmed_swaps_tx, confirmed_swaps_rx) =
            tokio::sync::mpsc::unbounded_channel::<Vec<ConfirmedSwap>>();

        let evm_rpc_clone = evm_rpc.clone();
        let btc_rpc_clone = btc_rpc.clone();
        let contract_data_engine_clone = contract_data_engine.clone();
        let bitcoin_data_engine_clone = bitcoin_data_engine.clone();

        let searcher_handle = tokio::spawn(async move {
            Self::search_for_swaps(
                evm_rpc_clone,
                btc_rpc_clone,
                contract_data_engine_clone,
                bitcoin_data_engine_clone,
                bitcoin_concurrency_limit,
                confirmed_swaps_tx,
            )
            .await
        });

        let btc_rpc_clone = btc_rpc.clone();
        let contract_data_engine_clone = contract_data_engine.clone();
        let bitcoin_data_engine_clone = bitcoin_data_engine.clone();
        let finalizer_handle = tokio::spawn(async move {
            Self::finalize_confirmed_swaps(
                confirmed_swaps_rx,
                btc_rpc_clone,
                bitcoin_data_engine_clone,
                contract_data_engine_clone,
            )
            .await
        });

        Self {
            contract_data_engine,
            bitcoin_data_engine,
            evm_rpc,
            btc_rpc,
            rift_exchange_address,
            searcher_handle,
            finalizer_handle,
        }
    }

    // called by search_for_swaps thread

    async fn search_for_swaps(
        evm_rpc: Arc<dyn Provider<PubSubFrontend>>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        contract_data_engine: Arc<DataEngine>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        bitcoin_concurrency_limit: usize,
        confirmed_swaps_tx: UnboundedSender<Vec<ConfirmedSwap>>,
    ) -> eyre::Result<()> {
        let mut block_subscribtion = bitcoin_data_engine.subscribe_to_new_blocks();

        let (start_search_bitcoin_block_number, end_search_bitcoin_block_number) =
            compute_block_search_range(
                evm_rpc,
                btc_rpc.clone(),
                contract_data_engine.clone(),
                bitcoin_data_engine.clone(),
            )
            .await?;

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
        let mut pending_swaps = Vec::new();

        loop {
            // Collect all available new blocks from the subscription
            if !first_run {
                // After the first run, await a new block before continuing
                let new_leaf = block_subscribtion.recv().await?;
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
            info!("Analyzing blocks {} for swaps", block_leaves.len());

            if first_run {
                first_run = false;
            }

            if block_leaves.is_empty() {
                continue;
            }

            let full_blocks = btc_rpc
                .get_blocks_from_leaves(&block_leaves, bitcoin_concurrency_limit)
                .await?;

            pending_swaps.extend(
                find_new_swaps_in_blocks(contract_data_engine.clone(), &full_blocks).await?,
            );

            let confirmed_swaps = find_pending_swaps_with_sufficient_confirmations(
                btc_rpc.clone(),
                &mut pending_swaps,
            )
            .await?;

            confirmed_swaps_tx.send(confirmed_swaps)?;

            // clear block leaves before looping back
            block_leaves.clear();
        }
    }

    async fn finalize_confirmed_swaps(
        mut confirmed_swaps_rx: UnboundedReceiver<Vec<ConfirmedSwap>>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        contract_data_engine: Arc<DataEngine>,
    ) -> eyre::Result<()> {
        loop {
            let confirmed_swaps = confirmed_swaps_rx.recv().await.unwrap();
            // TODO: Some validation that the TXNS are still in the longest chain and then pushing them back to the
            // pending swaps queue if they do not would be ideal
            // Assume for now that if the txns are here they're part of the longest chain
            // 1. Determine what the state of the onchain light client is (current tip)
            // 2. If it's equal to the locally stored chain, do nothing

            let btc_light_client_tip = contract_data_engine.get_mmr_root().await?;
            let btc_local_tip = bitcoin_data_engine
                .indexed_mmr
                .read()
                .await
                .get_root()
                .await?;

            if btc_light_client_tip != btc_local_tip {
                // TODO: Add logic to determine the light client update needed
            }
            // at this point we create the swap proof params
        }
    }
}

// Computes how far back in terms of bitcoin blocks to search for swaps based on the oldest active deposit
async fn compute_block_search_range(
    evm_rpc: Arc<dyn Provider<PubSubFrontend>>,
    btc_rpc: Arc<AsyncBitcoinClient>,
    contract_data_engine: Arc<DataEngine>,
    bitcoin_data_engine: Arc<BitcoinDataEngine>,
) -> eyre::Result<(u32, u32)> {
    let current_evm_timestamp = evm_rpc
        .get_block_by_number(
            alloy::eips::BlockNumberOrTag::Latest,
            alloy::rpc::types::BlockTransactionsKind::Hashes,
        )
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

    let oldest_active_deposit = contract_data_engine
        .get_oldest_active_deposit(current_evm_timestamp)
        .await?;

    let end_search_bitcoin_block_number = current_btc_tip as u32;

    let start_search_bitcoin_block_number =
        if let Some(oldest_active_deposit) = oldest_active_deposit {
            btc_rpc
                .find_oldest_block_before_timestamp(oldest_active_deposit.deposit.depositTimestamp)
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

async fn find_new_swaps_in_blocks(
    contract_data_engine: Arc<DataEngine>,
    blocks: &[Block],
) -> eyre::Result<Vec<PendingSwap>> {
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
    let mut pending_swaps = Vec::new();
    for block in blocks {
        for tx in block.txdata.clone() {
            // check if the tx is a swap
            let txid = tx.txid();
            for output in tx.output.clone() {
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
                let potential_deposit_vault_commitment: [u8; 32] =
                    script_pubkey_bytes[2..34].try_into()?;
                let chain_aware_deposit = contract_data_engine
                    .get_deposit_by_id(potential_deposit_vault_commitment)
                    .await?;
                if chain_aware_deposit.is_none() {
                    continue;
                }
                let chain_aware_deposit = chain_aware_deposit.unwrap();

                let serialized = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&tx);
                let mut reader = serialized.as_slice();
                let canon_bitcoin_tx =
                    bitcoin::Transaction::consensus_decode_from_finite_reader(&mut reader).unwrap();

                let tx_data_no_segwit = serialize_no_segwit(&canon_bitcoin_tx)?;

                let payment_validation = validate_bitcoin_payment(
                    &tx_data_no_segwit,
                    &chain_aware_deposit.deposit,
                    &potential_deposit_vault_commitment,
                );
                if payment_validation.is_err() {
                    info!(
                        "Invalid payment for deposit {} with bitcoin txid: {}, skipping...",
                        hex::encode(potential_deposit_vault_commitment),
                        txid
                    );
                    continue;
                }

                info!(
                    "Found a potential fill transaction for deposit {} with bitcoin txid: {}",
                    hex::encode(potential_deposit_vault_commitment),
                    txid
                );
                pending_swaps.push(PendingSwap {
                    chain_aware_deposit,
                    payment_txid: txid,
                });
            }
        }
    }

    Ok(pending_swaps)
}

async fn find_pending_swaps_with_sufficient_confirmations(
    btc_rpc: Arc<AsyncBitcoinClient>,
    pending_swaps: &mut Vec<PendingSwap>,
) -> eyre::Result<Vec<ConfirmedSwap>> {
    let mut confirmed_swaps = Vec::new();
    let mut i = 0;

    while i < pending_swaps.len() {
        // specifically don't pass a block hash here in the case that a reorg placed the txn
        // in a different block
        let txn_result = btc_rpc
            .get_raw_transaction_info(&pending_swaps[i].payment_txid, None)
            .await?;

        // Confirmations should always be set here b/c we're setting the verbose flag by calling
        // get_raw_transaction_info
        let confirmations = txn_result
            .confirmations
            .expect("Confirmations wasn't returned");

        if confirmations
            >= pending_swaps[i]
                .chain_aware_deposit
                .deposit
                .confirmationBlocks as u32
        {
            let block_leaf = btc_rpc
                .get_leaf_from_block_hash(
                    txn_result.blockhash.expect("Block hash wasn't proivided"),
                )
                .await?;
            let pending_swap = pending_swaps.remove(i);
            // This swap is confirmed, move it to confirmed_swaps
            confirmed_swaps.push(ConfirmedSwap {
                chain_aware_deposit: pending_swap.chain_aware_deposit,
                payment_txid: pending_swap.payment_txid,
                payment_block_leaf: block_leaf,
            })
            // Don't increment i since we've shifted the vector
        } else {
            // This swap is still pending
            i += 1;
        }
    }

    Ok(confirmed_swaps)
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
/// * `contract_data_engine` - The contract data engine that contains the current on-chain state
///
/// # Returns
///
/// A Result containing the ChainTransition if successful, or an error otherwise
pub async fn build_chain_transition_for_light_client_update(
    btc_rpc: Arc<AsyncBitcoinClient>,
    bitcoin_data_engine: &BitcoinDataEngine,
    contract_data_engine: &DataEngine,
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
        let light_client_mmr = contract_data_engine.checkpointed_block_tree.read().await;
        let bitcoin_mmr = bitcoin_data_engine.indexed_mmr.read().await;

        let current_mmr_root = contract_data_engine.get_mmr_root().await?;
        let current_mmr_bagged_peak = contract_data_engine.get_mmr_bagged_peak().await?;

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

        // get the peaks of the light client mmr as if the parent leaf was the tip of the MMR
        let parent_leaf_peaks = light_client_mmr.get_peaks(Some(parent_leaf_index)).await?;

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

    let parent_header: Header = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(
        &btc_rpc
            .get_block_header(&BlockHash::from_slice(&parent_with_proof.leaf.block_hash)?)
            .await?,
    )
    .try_into()
    .map_err(|e| eyre::eyre!("Failed to serialize parent header: {}", e))?;

    let parent_retarget_header: Header =
        bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(
            &btc_rpc
                .get_block_header(&BlockHash::from_slice(
                    &parent_retarget_with_proof.leaf.block_hash,
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
