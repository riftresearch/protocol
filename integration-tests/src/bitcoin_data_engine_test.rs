use std::sync::Arc;
use std::time::Duration;

use bitcoin_data_engine::BitcoinDataEngine;
use bitcoincore_rpc_async::Auth;
use corepc_node::client::bitcoin::Address as BitcoinAddress;
use corepc_node::{types::GetTransaction, Client as BitcoinClient, Node as BitcoinRegtest};
use rift_sdk::bitcoin_utils::AsyncBitcoinClient;
use rift_sdk::DatabaseLocation;
use tokio::signal;
use tokio::task::JoinSet;

use crate::test_utils::setup_test_tracing;

async fn setup_bitcoin_regtest_and_client() -> (
    BitcoinRegtest,
    AsyncBitcoinClient,
    BitcoinAddress,
    JoinSet<eyre::Result<()>>,
) {
    let mut join_set = JoinSet::new();
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
    (bitcoin_regtest, bitcoin_rpc, bitcoin_address, join_set)
}

#[tokio::test]
async fn test_simple_sync_and_read() {
    setup_test_tracing();
    let db_loc = DatabaseLocation::InMemory;
    let (bitcoin_regtest, bitcoin_rpc, bitcoin_address, mut join_set) =
        setup_bitcoin_regtest_and_client().await;
    let bitcoin_rpc = Arc::new(bitcoin_rpc);

    println!("Creating bitcoin data engine");
    let bitcoin_data_engine = BitcoinDataEngine::new(
        &db_loc,
        bitcoin_rpc,
        100,
        Duration::from_secs(1),
        &mut join_set,
    )
    .await;

    tokio::select! {
        _ = bitcoin_data_engine.wait_for_initial_sync() => {}
        result = join_set.join_next() => {
            println!("Thread error: {:?}", result);
            panic!("Bitcoin data engine failed to start");
        }
    }

    let mut new_block_subscription = bitcoin_data_engine.subscribe_to_new_blocks();

    // mine some blocks
    bitcoin_regtest
        .client
        .generate_to_address(5, &bitcoin_address)
        .unwrap();

    // wait for the new blocks to be downloaded
    for _ in 0..5 {
        let new_block_leaf = new_block_subscription.recv().await.unwrap();
        println!("New block leaf: {:?}", new_block_leaf);
    }
}
