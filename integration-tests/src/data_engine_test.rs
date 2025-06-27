use alloy::providers::ext::AnvilApi;
use bitcoin_light_client_core::{
    leaves::{create_new_leaves, get_genesis_leaf, BlockLeaf},
    light_client::{calculate_cumulative_work, Header},
};
use rift_indexer::engine::RiftIndexer;
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
    RiftIndexer::seed(
        &DatabaseLocation::Directory(dir_str.clone()),
        leaves.clone(),
    )
    .await
    .unwrap();

    // Re-open using the same database location
    let engine = RiftIndexer::seed(&DatabaseLocation::Directory(dir_str), Vec::new())
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
    RiftIndexer::seed(&DatabaseLocation::InMemory, leaves.clone())
        .await
        .unwrap();

    // Create a new instance using the same location and seed again
    let engine = RiftIndexer::seed(&DatabaseLocation::InMemory, leaves.clone())
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
async fn test_data_engine_handles_restart() {
    use alloy::{primitives::U256, providers::Provider, sol_types::SolEvent};
    use devnet::RiftDevnet;
    use rift_sdk::{
        create_websocket_wallet_provider, handle_background_thread_result, DatabaseLocation,
        MultichainAccount,
    };
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
        .funded_evm_address(maker.ethereum_address.to_string())
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
    let independent_engine = RiftIndexer::start(
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
            devnet.rift_indexer.get_tip_proof().await?;

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
    let restarted_engine = RiftIndexer::start(
        &DatabaseLocation::Directory(db_dir.clone()),
        devnet.ethereum.funded_provider.clone(),
        *rift_exchange.address(),
        0,      // deploy block number (will be ignored due to smart resumption)
        10000,  // log chunk size
        vec![], // no checkpoint leaves
        &mut new_join_set,
    )
    .await
    .expect("Failed to restart data engine");

    println!("Waiting for restarted initial sync...");

    tokio::select! {
        _ = restarted_engine.wait_for_initial_sync() => {
            println!("Restarted data engine initial sync complete");
        }
        result = new_join_set.join_next() => {
            if let Some(Err(e)) = result {
                panic!("Background thread failed during restart: {:?}", e);
            }
        }
    }

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

#[tokio::test]
async fn test_data_engine_handles_block_reorg() {
    use alloy::{hex, primitives::U256, providers::Provider, sol_types::SolEvent};
    use bitcoincore_rpc_async::RpcApi;
    use devnet::RiftDevnet;
    use hypernode::HypernodeArgs;
    use rift_sdk::{
        create_websocket_wallet_provider, handle_background_thread_result, DatabaseLocation,
        MultichainAccount, proof_generator::ProofGeneratorType, txn_broadcast::TransactionBroadcaster,
    };
    use sol_bindings::{BaseCreateOrderParams, CreateOrderParams, OrderCreated};
    use tokio::time::{sleep, timeout, Duration};

    // Create test accounts
    let maker = MultichainAccount::new(1);
    let taker = MultichainAccount::new(2);
    let hypernode_account = MultichainAccount::new(3);

    // Create temporary directory for our independent data engine database
    let temp_dir = tempfile::tempdir().unwrap();
    let db_dir = temp_dir.path().to_str().unwrap().to_string();

    // Setup devnet with in-memory database (we'll create our own data engine)
    let (mut devnet, _funded_sats) = RiftDevnet::builder()
        .funded_evm_address(maker.ethereum_address.to_string())
        .funded_evm_address(hypernode_account.ethereum_address.to_string())
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

    // Create our own independent data engine
    println!("Creating independent data engine with file-based database...");
    let mut join_set = tokio::task::JoinSet::new();
    let independent_engine = RiftIndexer::start(
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

    // Get the initial MMR root from the contract (which the data engine should sync with)
    let initial_mmr_root = devnet
        .ethereum
        .rift_exchange_contract
        .mmrRoot()
        .call()
        .await
        .expect("Failed to get initial MMR root from contract")
        .0;
    println!("Initial MMR root from contract: {}", hex::encode(initial_mmr_root));

    // Get the current block number before submitting order
    let block_before_order = devnet
        .ethereum
        .funded_provider
        .get_block_number()
        .await
        .expect("Failed to get block number");

    println!("Block before order: {}", block_before_order);

    // Submit an order
    println!("Submitting order...");
    let deposit_amount = U256::from(100_000_000u128);
    let expected_sats = 100_000_000u64;

    // Approve the RiftExchange to spend tokens
    let approve_call = token_contract.approve(*rift_exchange.address(), deposit_amount);
    maker_evm_provider
        .send_transaction(approve_call.into_transaction_request())
        .await
        .expect("Failed to approve tokens")
        .get_receipt()
        .await
        .expect("Failed to get approve receipt");

    // Get safe block proof data from devnet's data engine
    let (safe_leaf, safe_siblings, safe_peaks) = devnet
        .rift_indexer
        .get_tip_proof()
        .await
        .expect("Failed to get tip proof");

    // Create order parameters
    let deposit_params = CreateOrderParams {
        base: BaseCreateOrderParams {
            owner: maker.ethereum_address,
            bitcoinScriptPubKey: maker.bitcoin_wallet.get_p2wpkh_script().to_bytes().into(),
            salt: [0x11; 32].into(),
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
        .await
        .expect("Failed to submit order")
        .get_receipt()
        .await
        .expect("Failed to get order receipt");

    // Extract order from logs
    let order_created_log = OrderCreated::decode_log(
        &receipt
            .inner
            .logs()
            .iter()
            .find(|log| *log.topic0().unwrap() == OrderCreated::SIGNATURE_HASH)
            .unwrap()
            .inner,
    )
    .expect("Failed to decode order created log");

    let order = order_created_log.data.order;
    println!("Order submitted with index: {}", order.index);

    // Poll our independent data engine to verify it sees the order
    let order_seen = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Some(retrieved_order)) = independent_engine
                .get_order_by_index(order.index.to::<u64>())
                .await
            {
                println!(
                    "Independent data engine sees order: index={}",
                    retrieved_order.order.index
                );
                return true;
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("Timeout waiting for order to be seen by data engine");

    assert!(order_seen);

    // Mine Bitcoin blocks to trigger light client update
    println!("Mining Bitcoin blocks to trigger light client update...");
    let blocks_to_mine = 10;
    devnet
        .bitcoin
        .mine_blocks(blocks_to_mine)
        .await
        .expect("Failed to mine Bitcoin blocks");
    
    let bitcoin_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap() as u32;
    println!("Mined {} blocks, new Bitcoin height: {}", blocks_to_mine, bitcoin_height);

    // Create hypernode provider and transaction broadcaster
    let hypernode_evm_provider = create_websocket_wallet_provider(
        devnet.ethereum.anvil.ws_endpoint_url().as_str(),
        hypernode_account.secret_bytes,
    )
    .await
    .expect("Failed to create hypernode EVM provider");

    let _transaction_broadcaster = TransactionBroadcaster::new(
        std::sync::Arc::new(hypernode_evm_provider),
        devnet.ethereum.anvil.endpoint().to_string(),
        &mut devnet.join_set,
    );

    // Start hypernode with light client watchtower enabled
    let hypernode_args = HypernodeArgs {
        evm_ws_rpc: devnet.ethereum.anvil.ws_endpoint_url().to_string(),
        btc_rpc: devnet.bitcoin.rpc_url_with_cookie.clone(),
        private_key: hex::encode(hypernode_account.secret_bytes),
        checkpoint_file: devnet.checkpoint_file_handle.path().to_string_lossy().to_string(),
        database_location: DatabaseLocation::InMemory,
        rift_exchange_address: devnet.ethereum.rift_exchange_contract.address().to_string(),
        deploy_block_number: 0, // Start from beginning as independent data engine should catch up
        evm_log_chunk_size: 10000,
        btc_batch_rpc_size: 100,
        proof_generator: ProofGeneratorType::Execute,
        enable_auto_light_client_update: true,
        auto_light_client_update_block_lag_threshold: 3, // Trigger after 3 blocks behind
        auto_light_client_update_check_interval_secs: 1, // Check every 1 second
    };

    // Start hypernode in background
    println!("Starting hypernode with light client watchtower enabled...");
    let _hypernode_handle = devnet.join_set.spawn(async move {
        hypernode_args.run().await
    });

    // Wait for light client update to happen
    println!("Waiting for light client update to be processed...");
    let light_client_updated = timeout(Duration::from_secs(60), async {
        let initial_light_client_height = devnet
            .ethereum
            .rift_exchange_contract
            .lightClientHeight()
            .call()
            .await
            .expect("Failed to get initial light client height");

        loop {
            let current_height = devnet
                .ethereum
                .rift_exchange_contract
                .lightClientHeight()
                .call()
                .await
                .expect("Failed to get current light client height");

            if current_height > initial_light_client_height {
                println!(
                    "Light client updated from height {} to {}",
                    initial_light_client_height, current_height
                );
                return true;
            }
            sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("Timeout waiting for light client update");

    assert!(light_client_updated);

    // Get the new MMR root after light client update from the contract
    let new_mmr_root = devnet
        .ethereum
        .rift_exchange_contract
        .mmrRoot()
        .call()
        .await
        .expect("Failed to get new MMR root from contract")
        .0;
    println!("New MMR root after light client update: {}", hex::encode(new_mmr_root));
    
    // Verify MMR root changed
    assert_ne!(initial_mmr_root, new_mmr_root, "MMR root should have changed after light client update");

    // Give data engine time to process the light client update
    sleep(Duration::from_secs(3)).await;

    // Rollback to block before the order was submitted
    println!("Rolling back to block before order: {}", block_before_order);

    let current_block = devnet
        .ethereum
        .funded_provider
        .get_block_number()
        .await
        .expect("Failed to get current block number");
    let depth = current_block - block_before_order;
    println!("Rolling back {} blocks", depth);

    // Use anvil_rollback to revert to the block before the order
    devnet
        .ethereum
        .funded_provider
        .anvil_rollback(Some(depth))
        .await
        .expect("Rollback failed");

    // Verify the rollback worked
    let current_block = devnet
        .ethereum
        .funded_provider
        .get_block_number()
        .await
        .expect("Failed to get current block number");

    println!("Block after rollback: {}", current_block);
    assert_eq!(current_block, block_before_order);

    // Mine 1 new EVM block to trigger the WebSocket block listener and reorg detection
    println!("Mining 1 EVM block to trigger reorg detection...");
    devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(1), None)
        .await
        .expect("Failed to mine EVM block");

    // Give the data engine some time to detect the reorg and process it
    sleep(Duration::from_secs(5)).await;

    // Poll the data engine to verify it removes the order
    println!("Verifying order is removed from data engine after reorg...");
    let order_removed = timeout(Duration::from_secs(30), async {
        loop {
            match independent_engine
                .get_order_by_index(order.index.to::<u64>())
                .await
            {
                Ok(None) => {
                    println!("Order successfully removed from data engine after reorg");
                    return true;
                }
                Ok(Some(_)) => {
                    println!(
                        "Order still exists in data engine, waiting for reorg to be processed..."
                    );
                    sleep(Duration::from_millis(1000)).await;
                }
                Err(e) => {
                    println!("Error querying order: {:?}", e);
                    sleep(Duration::from_millis(1000)).await;
                }
            }
        }
    })
    .await
    .expect("Timeout waiting for order to be removed after reorg");

    assert!(order_removed);

    // Poll to verify contract MMR root doesn't change after reorg  
    // (since we rolled back to before the order, the light client update should also be rolled back)
    println!("Verifying contract MMR root remains at initial state after reorg...");
    let mmr_reverted = timeout(Duration::from_secs(30), async {
        loop {
            let current_mmr_root = devnet
                .ethereum
                .rift_exchange_contract
                .mmrRoot()
                .call()
                .await
                .expect("Failed to get current MMR root from contract")
                .0;
            
            if current_mmr_root == initial_mmr_root {
                println!(
                    "Contract MMR root remains at initial state (as expected): {}",
                    hex::encode(current_mmr_root)
                );
                return true;
            } else {
                println!(
                    "Warning: Contract MMR root differs from initial state, current: {}, expected: {}",
                    hex::encode(current_mmr_root),
                    hex::encode(initial_mmr_root)
                );
                // This might be expected if the light client update transaction wasn't rolled back
                // Let's check if the independent data engine at least removed the light client update
                sleep(Duration::from_millis(1000)).await;
            }
        }
    })
    .await
    .expect("Timeout waiting for MMR root verification after reorg");

    assert!(mmr_reverted);

    println!("Test passed! Data engine successfully handled block reorg:");
    println!("  ✓ Order was removed");
    println!("  ✓ MMR root reverted to initial state");
    println!("  ✓ Light client update was rolled back");

    // Clean up
    join_set.abort_all();
}

#[tokio::test]
async fn test_data_engine_handles_reorg_while_down() {
    use alloy::{hex, primitives::U256, providers::Provider, sol_types::SolEvent};
    use devnet::RiftDevnet;
    use rift_sdk::{
        create_websocket_wallet_provider, DatabaseLocation,
        MultichainAccount,
    };
    use sol_bindings::{BaseCreateOrderParams, CreateOrderParams, OrderCreated};
    use tokio::time::{sleep, timeout, Duration};

    // Create test accounts
    let maker = MultichainAccount::new(1);
    let taker = MultichainAccount::new(2);

    // Create temporary directory for our independent data engine database
    let temp_dir = tempfile::tempdir().unwrap();
    let db_dir = temp_dir.path().to_str().unwrap().to_string();

    // Setup devnet with in-memory database (we'll create our own data engine)
    let (mut devnet, _funded_sats) = RiftDevnet::builder()
        .funded_evm_address(maker.ethereum_address.to_string())
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

    // Create our own independent data engine
    println!("Creating independent data engine with file-based database...");
    let mut join_set = tokio::task::JoinSet::new();
    let independent_engine = RiftIndexer::start(
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

    // Get the current block number before submitting order
    let block_before_order = devnet
        .ethereum
        .funded_provider
        .get_block_number()
        .await
        .expect("Failed to get block number");

    println!("Block before order: {}", block_before_order);

    // Submit an order
    println!("Submitting order...");
    let deposit_amount = U256::from(100_000_000u128);
    let expected_sats = 100_000_000u64;

    // Approve the RiftExchange to spend tokens
    let approve_call = token_contract.approve(*rift_exchange.address(), deposit_amount);
    maker_evm_provider
        .send_transaction(approve_call.into_transaction_request())
        .await
        .expect("Failed to approve tokens")
        .get_receipt()
        .await
        .expect("Failed to get approve receipt");

    // Get safe block proof data from devnet's data engine
    let (safe_leaf, safe_siblings, safe_peaks) = devnet
        .rift_indexer
        .get_tip_proof()
        .await
        .expect("Failed to get tip proof");

    // Create order parameters
    let deposit_params = CreateOrderParams {
        base: BaseCreateOrderParams {
            owner: maker.ethereum_address,
            bitcoinScriptPubKey: maker.bitcoin_wallet.get_p2wpkh_script().to_bytes().into(),
            salt: [0x11; 32].into(),
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
        .await
        .expect("Failed to submit order")
        .get_receipt()
        .await
        .expect("Failed to get order receipt");

    // Extract order from logs
    let order_created_log = OrderCreated::decode_log(
        &receipt
            .inner
            .logs()
            .iter()
            .find(|log| *log.topic0().unwrap() == OrderCreated::SIGNATURE_HASH)
            .unwrap()
            .inner,
    )
    .expect("Failed to decode order created log");

    let order = order_created_log.data.order;
    println!("Order submitted with index: {}", order.index);

    // Poll our independent data engine to verify it sees the order
    let order_seen = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Some(retrieved_order)) = independent_engine
                .get_order_by_index(order.index.to::<u64>())
                .await
            {
                println!(
                    "Independent data engine sees order: index={}",
                    retrieved_order.order.index
                );
                return true;
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("Timeout waiting for order to be seen by data engine");

    assert!(order_seen);

    // STEP 1: Stop the data engine (simulate going offline)
    println!("Stopping independent data engine...");
    join_set.abort_all();

    // Give it a moment to fully shut down
    sleep(Duration::from_secs(2)).await;

    // STEP 2: Rollback to block before the order was submitted (while data engine is down)
    println!("Rolling back to block before order while data engine is down: {}", block_before_order);

    let current_block = devnet
        .ethereum
        .funded_provider
        .get_block_number()
        .await
        .expect("Failed to get current block number");
    let depth = current_block - block_before_order;
    println!("Rolling back {} blocks", depth);

    // Use anvil_rollback to revert to the block before the order
    devnet
        .ethereum
        .funded_provider
        .anvil_rollback(Some(depth))
        .await
        .expect("Rollback failed");

    // Verify the rollback worked
    let current_block = devnet
        .ethereum
        .funded_provider
        .get_block_number()
        .await
        .expect("Failed to get current block number");

    println!("Block after rollback: {}", current_block);
    assert_eq!(current_block, block_before_order);

    // STEP 3: Restart data engine with same DB location (this should detect reorg on startup)
    println!("Restarting independent data engine with same database location...");
    let mut new_join_set = tokio::task::JoinSet::new();
    let restarted_engine = RiftIndexer::start(
        &DatabaseLocation::Directory(db_dir.clone()),
        devnet.ethereum.funded_provider.clone(),
        *rift_exchange.address(),
        0,      // deploy block number (will be ignored due to smart resumption)
        10000,  // log chunk size
        vec![], // no checkpoint leaves
        &mut new_join_set,
    )
    .await
    .expect("Failed to restart data engine");

    println!("Waiting for restarted initial sync...");

    tokio::select! {
        _ = restarted_engine.wait_for_initial_sync() => {
            println!("Restarted data engine initial sync complete");
        }
        result = new_join_set.join_next() => {
            if let Some(Err(e)) = result {
                panic!("Background thread failed during restart: {:?}", e);
            }
        }
    }

    // STEP 4: Verify the data engine detected the reorg on startup and removed the invalid order
    println!("Verifying order was removed after reorg detection on startup...");
    let order_removed = timeout(Duration::from_secs(30), async {
        loop {
            match restarted_engine
                .get_order_by_index(order.index.to::<u64>())
                .await
            {
                Ok(None) => {
                    println!("Order successfully removed from data engine after reorg detection on startup");
                    return true;
                }
                Ok(Some(_)) => {
                    println!(
                        "Order still exists in data engine, waiting for startup validation to complete..."
                    );
                    sleep(Duration::from_millis(1000)).await;
                }
                Err(e) => {
                    println!("Error querying order: {:?}", e);
                    sleep(Duration::from_millis(1000)).await;
                }
            }
        }
    })
    .await
    .expect("Timeout waiting for order to be removed after startup reorg detection");

    assert!(order_removed);

    println!("Test passed! Data engine successfully detected reorg on startup and removed invalid order");

    // Clean up
    new_join_set.abort_all();
}
