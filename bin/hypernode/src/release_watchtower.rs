use std::sync::Arc;

use alloy::{
    eips::BlockId,
    primitives::Address,
    providers::{DynProvider, Provider},
    pubsub::SubscriptionStream,
    rpc::types::Header,
};
use data_engine::engine::ContractDataEngine;
use futures::{
    future::Ready,
    stream::{self, Chain, Once},
    Stream, StreamExt,
};
use rift_sdk::RiftExchangeHarnessClient;
use sol_bindings::{RiftExchangeHarnessInstance, SettleOrderParams};
use tokio::{sync::watch, task::JoinSet};
use tracing::{debug, info, info_span, Instrument};

use rift_sdk::txn_broadcast::{PreflightCheck, TransactionBroadcaster};

async fn pump_blocks_into_watch(
    mut block_stream: impl Stream<Item = Header> + Unpin,
    tx: watch::Sender<Option<Header>>,
) -> eyre::Result<()> {
    while let Some(block) = block_stream.next().await {
        // Sending overwrites any previous block
        let _ = tx.send(Some(block));
    }
    // Should never return, just to make all long running tasks return a result
    Ok(())
}

pub struct ReleaseWatchtower;

impl ReleaseWatchtower {
    pub async fn run(
        rift_exchange_address: Address,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        evm_rpc: DynProvider,
        contract_data_engine: Arc<ContractDataEngine>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> eyre::Result<Self> {
        let (tx, rx) = watch::channel(None);

        let combined_stream = setup_block_stream(evm_rpc.clone()).await?;

        join_set.spawn(async move { pump_blocks_into_watch(combined_stream, tx).await });

        join_set.spawn(
            async move {
                search_on_new_evm_blocks(
                    rift_exchange_address,
                    transaction_broadcaster,
                    evm_rpc,
                    contract_data_engine,
                    rx,
                )
                .await
            }
            .instrument(info_span!("Release Watchtower")),
        );

        Ok(Self {})
    }
}

async fn setup_block_stream(
    evm_rpc: DynProvider,
) -> eyre::Result<Chain<Once<Ready<Header>>, SubscriptionStream<Header>>> {
    let current_block_header = evm_rpc
        .get_block(BlockId::latest())
        .await?
        .ok_or_else(|| eyre::eyre!("Failed to get current block"))?
        .header;

    // Convert the block subscription to a stream
    let sub = evm_rpc.subscribe_blocks().await?.into_stream();

    // Prepend the current block so the subscription starts immediately
    let combined_stream =
        stream::once(futures::future::ready(current_block_header.clone())).chain(sub);

    Ok(combined_stream)
}

async fn search_on_new_evm_blocks(
    rift_exchange_address: Address,
    transaction_broadcaster: Arc<TransactionBroadcaster>,
    evm_rpc: DynProvider,
    contract_data_engine: Arc<ContractDataEngine>,
    mut rx: watch::Receiver<Option<Header>>,
) -> eyre::Result<()> {
    let rift_exchange = RiftExchangeHarnessInstance::new(rift_exchange_address, evm_rpc);
    // Consume blocks from the watch
    while rx.changed().await.is_ok() {
        // Borrow the newest header, clone it, and drop the borrow immediately.
        let maybe_latest = rx.borrow().clone();

        if let Some(latest_block_header) = maybe_latest {
            search_for_releases(
                &rift_exchange,
                transaction_broadcaster.clone(),
                contract_data_engine.clone(),
                latest_block_header.timestamp,
            )
            .await?;
        }
    }

    Ok(())
}
async fn search_for_releases(
    rift_exchange: &RiftExchangeHarnessClient,
    transaction_broadcaster: Arc<TransactionBroadcaster>,
    contract_data_engine: Arc<ContractDataEngine>,
    block_timestamp: u64,
) -> eyre::Result<()> {
    debug!(
        "Searching for releases at evm block timestamp {}",
        block_timestamp
    );
    let swaps_ready_to_be_released = contract_data_engine
        .get_payments_ready_to_be_settled(block_timestamp)
        .await?;

    if swaps_ready_to_be_released.is_empty() {
        return Ok(());
    }

    info!(
        "Found {} swaps ready to be released",
        swaps_ready_to_be_released.len()
    );

    // We’ll build these params, but we have to be careful never to hold the read guard
    // across awaits. So we do *short* scoped reads for each piece.
    let mut release_liquidity_params = Vec::new();

    // Step 1: Grab the tip block height (lock scope is *only* for these few lines).
    let tip_block_height = {
        let tree = contract_data_engine.checkpointed_block_tree.read().await;
        // If get_leaf_count is truly async, you need to restructure that.
        // For demonstration, let's assume it's synchronous or you do not hold `tree` across the await.
        (tree.get_leaf_count().await? - 1) as u32
        // Guard is dropped immediately here.
    };

    // Step 2: For each swap, gather the proof. We do repeated short lock scopes so we
    // never hold it over an `.await`.
    for swap_with_deposit in &swaps_ready_to_be_released {
        let block_leaf = swap_with_deposit
            .payment
            .payment
            .paymentBitcoinBlockLeaf
            .clone();
        let swap_index = swap_with_deposit.payment.payment.index;

        // Acquire the lock in a tight scope:
        let proof = {
            let tree = contract_data_engine.checkpointed_block_tree.read().await;
            tree.get_circuit_proof(block_leaf.height as usize, None)
                .await
        };

        let proof = match proof {
            Ok(p) => p,
            Err(e) => {
                info!(
                    "Failed to get proof for block leaf {:?} not processing swap index {}: {:?}",
                    block_leaf, swap_index, e
                );
                continue;
            }
        };

        let bitcoin_swap_block_siblings = proof.siblings.iter().map(From::from).collect();
        let bitcoin_swap_block_peaks = proof.peaks.iter().map(From::from).collect();
        let utilized_vault = swap_with_deposit.order.order.clone();

        release_liquidity_params.push(SettleOrderParams {
            payment: swap_with_deposit.payment.payment.clone(),
            order: swap_with_deposit.order.order.clone(),
            paymentBitcoinBlockSiblings: bitcoin_swap_block_siblings,
            paymentBitcoinBlockPeaks: bitcoin_swap_block_peaks,
            tipBlockHeight: tip_block_height,
        });
    }

    if release_liquidity_params.is_empty() {
        info!("No release liquidity params found after processing all swaps");
        return Ok(());
    }

    // Now we can do our EVM transaction.
    let release_tx = rift_exchange.settleOrders(release_liquidity_params);
    let calldata = release_tx.calldata().to_owned();
    let transaction_request = release_tx.into_transaction_request();
    let transaction_result = transaction_broadcaster
        .broadcast_transaction(calldata, transaction_request, PreflightCheck::Simulate)
        .await?;

    info!("Transaction result: {:?}", transaction_result);
    // TODO: handle the transaction result

    Ok(())
}
