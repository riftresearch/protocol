use bitcoin_light_client_core::{
    leaves::{create_new_leaves, get_genesis_leaf, BlockLeaf},
    light_client::{calculate_cumulative_work, Header},
};
use data_engine::engine::ContractDataEngine;
use rift_sdk::DatabaseLocation;
use test_data_utils::TEST_HEADERS;

fn get_test_data() -> Vec<BlockLeaf> {
    let headers = TEST_HEADERS
        .clone()
        .iter()
        .map(|(_, h)| Header::new(h))
        .collect::<Vec<_>>();
    let (cumulative_chainworks, _) = calculate_cumulative_work(crypto_bigint::U256::ZERO, &headers);
    create_new_leaves(&get_genesis_leaf(), &headers, &cumulative_chainworks)
}

// TODO: Compared with test_data_engine_in_memory_db, it's obvious* the file based DB is much slower
// We need to figure out how to speed up the underyling sqlite operations, perhap through modifying the
// MMR library to support sqlite batching or by improving the underlying SQL queries.
// Benchmark difference:
// * cargo test --release test_data_engine_in_memory_db -- --nocapture
// * vs
// * cargo test --release test_data_engine_file_db -- --nocapture
#[tokio::test]
async fn test_data_engine_file_db() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dir_str = temp_dir.path().to_str().unwrap().to_string();

    let leaves = get_test_data();

    // Seed the database
    ContractDataEngine::seed(
        &DatabaseLocation::Directory(dir_str.clone()),
        leaves.clone(),
    )
    .await
    .unwrap();

    // Re-open using the same database location
    let engine = ContractDataEngine::seed(&DatabaseLocation::Directory(dir_str), Vec::new())
        .await
        .unwrap();

    // Verify the first leaf matches the seeded data
    let retrieved = engine
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_by_leaf_index(0)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(retrieved, leaves[0]);
}

#[tokio::test]
async fn test_data_engine_in_memory_db() {
    let leaves = get_test_data();

    // Initial seeding
    ContractDataEngine::seed(&DatabaseLocation::InMemory, leaves.clone())
        .await
        .unwrap();

    // Create a new instance using the same location and seed again
    let engine = ContractDataEngine::seed(&DatabaseLocation::InMemory, leaves.clone())
        .await
        .unwrap();

    let retrieved = engine
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_by_leaf_index(0)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(retrieved, leaves[0]);
}

#[tokio::test]
async fn test_data_engine_handles_restart_properly() {
    use alloy::{primitives::U256, providers::Provider, sol_types::SolEvent};
    use devnet::RiftDevnet;
    use rift_sdk::{create_websocket_wallet_provider, DatabaseLocation, MultichainAccount};
    use sol_bindings::{BaseCreateOrderParams, CreateOrderParams, OrderCreated};
    use tokio::time::{sleep, timeout, Duration};

    // Create test accounts
    let maker = MultichainAccount::new(1);
    let taker = MultichainAccount::new(2);

    // Create temporary directory for our independent data engine database
    let temp_dir = tempfile::tempdir().unwrap();
    let db_dir = temp_dir.path().to_str().unwrap().to_string();

    // Setup devnet with in-memory database (we'll create our own data engine)
    let (devnet, _funded_sats) = RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(maker.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
        .expect("Failed to build devnet");

    let maker_evm_provider = create_websocket_wallet_provider(
        devnet.ethereum.anvil.ws_endpoint_url().to_string().as_str(),
        maker.secret_bytes,
    )
    .await
    .expect("Failed to create maker evm provider");

    // Quick references
    let rift_exchange = devnet.ethereum.rift_exchange_contract.clone();
    let token_contract = devnet.ethereum.token_contract.clone();

    // Step 1: Create our own independent data engine
    println!("Creating independent data engine with file-based database...");
    let mut join_set = tokio::task::JoinSet::new();
    let independent_engine = ContractDataEngine::start(
        &DatabaseLocation::Directory(db_dir.clone()),
        devnet.ethereum.funded_provider.clone(),
        *rift_exchange.address(),
        0,      // deploy block number
        10000,  // log chunk size
        vec![], // no checkpoint leaves
        &mut join_set,
    )
    .await
    .expect("Failed to create independent data engine");

    // Wait for initial sync
    independent_engine
        .wait_for_initial_sync()
        .await
        .expect("Failed to wait for initial sync");

    // Helper function to create and submit an order
    async fn submit_order(
        maker: &MultichainAccount,
        taker: &MultichainAccount,
        maker_evm_provider: &impl alloy::providers::Provider,
        token_contract: &devnet::TokenizedBTCWebsocket,
        rift_exchange: &devnet::RiftExchangeHarnessWebsocket,
        devnet: &RiftDevnet,
        salt: [u8; 32],
    ) -> eyre::Result<sol_bindings::Order> {
        let deposit_amount = U256::from(100_000_000u128);
        let expected_sats = 100_000_000u64;

        // Approve the RiftExchange to spend tokens
        let approve_call = token_contract.approve(*rift_exchange.address(), deposit_amount);
        maker_evm_provider
            .send_transaction(approve_call.into_transaction_request())
            .await?
            .get_receipt()
            .await?;

        // Get safe block proof data from devnet's data engine
        let (safe_leaf, safe_siblings, safe_peaks) =
            devnet.contract_data_engine.get_tip_proof().await?;

        // Create order parameters
        let deposit_params = CreateOrderParams {
            base: BaseCreateOrderParams {
                owner: maker.ethereum_address,
                bitcoinScriptPubKey: maker.bitcoin_wallet.get_p2wpkh_script().to_bytes().into(),
                salt: salt.into(),
                confirmationBlocks: 2,
                safeBlockLeaf: safe_leaf.into(),
            },
            expectedSats: expected_sats,
            depositAmount: deposit_amount,
            designatedReceiver: taker.ethereum_address,
            safeBlockSiblings: safe_siblings.iter().map(From::from).collect(),
            safeBlockPeaks: safe_peaks.iter().map(From::from).collect(),
        };

        // Submit the order
        let deposit_call = rift_exchange.createOrder(deposit_params);
        let receipt = maker_evm_provider
            .send_transaction(deposit_call.into_transaction_request())
            .await?
            .get_receipt()
            .await?;

        // Extract order from logs
        let order_created_log = OrderCreated::decode_log(
            &receipt
                .inner
                .logs()
                .iter()
                .find(|log| *log.topic0().unwrap() == OrderCreated::SIGNATURE_HASH)
                .unwrap()
                .inner,
        )?;

        Ok(order_created_log.data.order)
    }

    // Step 2: Submit first order and verify our data engine sees it
    println!("Submitting first order...");
    let first_order = submit_order(
        &maker,
        &taker,
        &maker_evm_provider,
        &token_contract,
        &rift_exchange,
        &devnet,
        [0x11; 32],
    )
    .await
    .expect("Failed to submit first order");

    // Poll our independent data engine to verify it sees the first order
    let first_order_seen = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Some(order)) = independent_engine
                .get_order_by_index(first_order.index.to::<u64>())
                .await
            {
                println!(
                    "Independent data engine sees first order: index={}",
                    order.order.index
                );
                return true;
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("Timeout waiting for first order");

    assert!(first_order_seen);

    // Step 3: Stop our data engine by aborting the join_set
    println!("Stopping independent data engine...");
    join_set.abort_all();

    // Give it a moment to fully shut down
    sleep(Duration::from_secs(2)).await;

    // Step 4: Submit second order while our data engine is down
    println!("Submitting second order while independent data engine is down...");
    let second_order = submit_order(
        &maker,
        &taker,
        &maker_evm_provider,
        &token_contract,
        &rift_exchange,
        &devnet,
        [0x22; 32],
    )
    .await
    .expect("Failed to submit second order");

    // Step 5: Restart data engine with same DB location
    println!("Restarting independent data engine with same database location...");
    let mut new_join_set = tokio::task::JoinSet::new();
    let restarted_engine = ContractDataEngine::start(
        &DatabaseLocation::Directory(db_dir.clone()),
        devnet.ethereum.funded_provider.clone(),
        *rift_exchange.address(),
        0,      // deploy block number
        10000,  // log chunk size
        vec![], // no checkpoint leaves
        &mut new_join_set,
    )
    .await
    .expect("Failed to restart data engine");

    // Wait for initial sync to complete
    restarted_engine
        .wait_for_initial_sync()
        .await
        .expect("Failed to wait for initial sync");

    // Step 6: Verify data engine sees both orders
    println!("Verifying restarted data engine sees both orders...");

    // Check first order is still there
    let first_order_check = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Some(order)) = restarted_engine
                .get_order_by_index(first_order.index.to::<u64>())
                .await
            {
                println!(
                    "Restarted data engine sees first order: index={}",
                    order.order.index
                );
                return true;
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("Timeout waiting for first order after restart");

    assert!(first_order_check);

    // Check second order is there
    let second_order_check = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Some(order)) = restarted_engine
                .get_order_by_index(second_order.index.to::<u64>())
                .await
            {
                println!(
                    "Restarted data engine sees second order: index={}",
                    order.order.index
                );
                return true;
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("Timeout waiting for second order after restart");

    assert!(second_order_check);

    // Additional verification: Check order details match
    let retrieved_first = restarted_engine
        .get_order_by_index(first_order.index.to::<u64>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_first.order.salt, first_order.salt);

    let retrieved_second = restarted_engine
        .get_order_by_index(second_order.index.to::<u64>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_second.order.salt, second_order.salt);

    println!("Test passed! Data engine successfully recovered both orders after restart.");

    // Clean up
    new_join_set.abort_all();
}
