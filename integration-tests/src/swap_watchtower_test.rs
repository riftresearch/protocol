use std::sync::Arc;

use devnet::{RiftDevnet, RiftExchangeWebsocket};
use hypernode::{swap_watchtower::SwapWatchtower, txn_broadcast::TransactionBroadcaster};
use rift_sdk::{
    proof_generator::{ProofGeneratorType, RiftProofGenerator},
    DatabaseLocation,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

use crate::test_utils::{
    setup_tracing_subscriber_with_log_watcher, MultichainAccount, WaitForLogLayer,
};

async fn setup_watchtower(sender_derivation_salt: u32) -> (RiftDevnet, Arc<RiftExchangeWebsocket>) {
    let proof_generator_handle =
        tokio::task::spawn_blocking(|| RiftProofGenerator::new(ProofGeneratorType::Execute));
    let hypernode_account = MultichainAccount::new(sender_derivation_salt);
    let (mut devnet, _funding_sats) = RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(hypernode_account.ethereum_address.to_string())
        .build()
        .await
        .unwrap();

    let rift_exchange = devnet.ethereum.rift_exchange_contract.clone();

    let transaction_broadcaster = Arc::new(TransactionBroadcaster::new(
        devnet.ethereum.funded_provider.clone(),
        devnet.ethereum.anvil.ws_endpoint_url().as_str().to_string(),
        &mut devnet.join_set,
    ));

    let proof_generator = proof_generator_handle.await.unwrap();

    SwapWatchtower::run(
        devnet.contract_data_engine.clone(),
        devnet.bitcoin.data_engine.clone(),
        devnet.ethereum.funded_provider.clone(),
        devnet.bitcoin.rpc_client.clone(),
        *rift_exchange.address(),
        transaction_broadcaster.clone(),
        100,
        Arc::new(proof_generator),
        &mut devnet.join_set,
    );

    (devnet, rift_exchange)
}

#[tokio::test]
async fn test_swap_watchtower_detects_block_and_submits_swap_proof() {
    let (devnet, rift_exchange) = setup_watchtower(1).await;
}
