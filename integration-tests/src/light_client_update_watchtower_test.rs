use bitcoincore_rpc_async::RpcApi;
use devnet::RiftDevnet;
use hypernode::HypernodeArgs;
use rift_sdk::{
    create_websocket_wallet_provider, proof_generator::ProofGeneratorType,
    txn_broadcast::TransactionBroadcaster, DatabaseLocation, MultichainAccount,
};
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// Tests that the light client update watchtower automatically updates the light client
/// when it falls behind the Bitcoin tip by more than the configured threshold.
#[tokio::test]
async fn test_light_client_update_watchtower_automatic_update() {
    // Setup devnet with Bitcoin enabled
    let hypernode_account = MultichainAccount::new(151);
    let (mut devnet, deploy_block_number) = RiftDevnet::builder()
        .funded_evm_address(hypernode_account.ethereum_address.to_string())
        .build()
        .await
        .expect("Failed to build devnet");

    println!("Devnet setup complete");

    // Get initial state
    let initial_bitcoin_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap() as u32;
    let initial_light_client_height = devnet
        .ethereum
        .rift_exchange_contract
        .lightClientHeight()
        .call()
        .await
        .unwrap();

    println!(
        "Initial Bitcoin height: {}, Light client height: {}",
        initial_bitcoin_height, initial_light_client_height
    );

    // Create hypernode with light client update watchtower enabled
    let evm_provider = create_websocket_wallet_provider(
        devnet.ethereum.anvil.ws_endpoint_url().as_str(),
        hypernode_account.secret_bytes,
    )
    .await
    .expect("Failed to create EVM provider");

    let _transaction_broadcaster = TransactionBroadcaster::new(
        std::sync::Arc::new(evm_provider),
        devnet.ethereum.anvil.endpoint(),
        1, // confirmations
        &mut devnet.join_set,
    );

    // Configure watchtower with aggressive settings for testing
    let block_lag_threshold = 3u32; // Trigger after 3 blocks behind
    let check_interval_secs = 1u64; // Check every 1 second

    let hypernode_args = HypernodeArgs {
        evm_ws_rpc: devnet.ethereum.anvil.ws_endpoint_url().to_string(),
        btc_rpc: devnet.bitcoin.rpc_url_with_cookie.clone(),
        private_key: hex::encode(hypernode_account.secret_bytes),
        checkpoint_file: devnet
            .checkpoint_file_handle
            .path()
            .to_string_lossy()
            .to_string(),
        database_location: DatabaseLocation::InMemory,
        rift_exchange_address: devnet.ethereum.rift_exchange_contract.address().to_string(),
        deploy_block_number,
        evm_log_chunk_size: 10000,
        btc_batch_rpc_size: 100,
        proof_generator: ProofGeneratorType::Execute,
        enable_auto_light_client_update: true,
        auto_light_client_update_block_lag_threshold: block_lag_threshold,
        auto_light_client_update_check_interval_secs: check_interval_secs,
        confirmations: 1,
    };

    // Start hypernode in background task
    let hypernode_handle = devnet.join_set.spawn(async move {
        println!("Starting hypernode with light client update watchtower enabled");
        hypernode_args.run().await
    });

    // Mine enough blocks to exceed the threshold
    let blocks_to_mine = block_lag_threshold + 2; // Mine 5 blocks (3 threshold + 2 extra)
    println!("Mining {} blocks to trigger watchtower", blocks_to_mine);

    devnet
        .bitcoin
        .mine_blocks(blocks_to_mine as u64)
        .await
        .expect("Failed to mine blocks");

    let new_bitcoin_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap() as u32;
    println!("New Bitcoin height: {}", new_bitcoin_height);

    // Wait for the watchtower to detect the lag and update the light client
    // The watchtower checks every 2 seconds, so we give it up to 30 seconds
    let timeout_duration = Duration::from_secs(30);
    let start_time = std::time::Instant::now();

    println!("Waiting for light client update watchtower to sync...");

    let update_successful = timeout(timeout_duration, async {
        loop {
            let current_light_client_height = devnet
                .ethereum
                .rift_exchange_contract
                .lightClientHeight()
                .call()
                .await
                .unwrap();

            println!(
                "Current light client height: {} (target: {})",
                current_light_client_height, new_bitcoin_height
            );

            // Check if light client has been updated to the new Bitcoin height
            if current_light_client_height >= new_bitcoin_height {
                println!(
                    "✅ Light client successfully updated to height {} in {:?}",
                    current_light_client_height,
                    start_time.elapsed()
                );
                return true;
            }

            // Sleep before next check
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await;

    // Verify the update was successful
    match update_successful {
        Ok(true) => {
            println!("✅ Test passed: Light client update watchtower successfully updated the light client");
        }
        Ok(false) => unreachable!(), // The loop only returns true
        Err(_) => {
            let final_light_client_height = devnet
                .ethereum
                .rift_exchange_contract
                .lightClientHeight()
                .call()
                .await
                .unwrap();

            panic!(
                "❌ Test failed: Light client update watchtower did not update within timeout. \
                 Bitcoin height: {}, Light client height: {}, Lag: {}",
                new_bitcoin_height,
                final_light_client_height,
                new_bitcoin_height.saturating_sub(final_light_client_height)
            );
        }
    }

    // Verify the MMR root was also updated
    let final_mmr_root = devnet
        .ethereum
        .rift_exchange_contract
        .mmrRoot()
        .call()
        .await
        .unwrap();

    let data_engine_mmr_root = devnet.rift_indexer.get_mmr_root().await.unwrap();

    println!("Final contract MMR root: {}", hex::encode(final_mmr_root));
    println!(
        "Data engine MMR root: {}",
        hex::encode(data_engine_mmr_root)
    );

    // The contract MMR root should match the data engine MMR root after the update
    assert_eq!(
        final_mmr_root.0, data_engine_mmr_root,
        "Contract MMR root should match data engine MMR root after light client update"
    );

    println!("✅ All assertions passed");

    // Clean shutdown
    hypernode_handle.abort();
}

/// Tests that the light client update watchtower remains idle when disabled
#[tokio::test]
async fn test_light_client_update_watchtower_disabled() {
    // Setup devnet with Bitcoin enabled
    let hypernode_account = MultichainAccount::new(151);
    let (mut devnet, deploy_block_number) = RiftDevnet::builder()
        .funded_evm_address(hypernode_account.ethereum_address.to_string())
        .build()
        .await
        .expect("Failed to build devnet");

    println!("Devnet setup complete");

    // Get initial state
    let initial_bitcoin_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap() as u32;
    let initial_light_client_height = devnet
        .ethereum
        .rift_exchange_contract
        .lightClientHeight()
        .call()
        .await
        .unwrap();

    println!(
        "Initial Bitcoin height: {}, Light client height: {}",
        initial_bitcoin_height, initial_light_client_height
    );

    let hypernode_args = HypernodeArgs {
        evm_ws_rpc: devnet.ethereum.anvil.ws_endpoint_url().to_string(),
        btc_rpc: devnet.bitcoin.rpc_url_with_cookie.clone(),
        private_key: hex::encode(hypernode_account.secret_bytes),
        checkpoint_file: devnet
            .checkpoint_file_handle
            .path()
            .to_string_lossy()
            .to_string(),
        database_location: DatabaseLocation::InMemory,
        rift_exchange_address: devnet.ethereum.rift_exchange_contract.address().to_string(),
        deploy_block_number,
        evm_log_chunk_size: 10000,
        btc_batch_rpc_size: 100,
        proof_generator: ProofGeneratorType::Execute,
        enable_auto_light_client_update: false, // DISABLED
        auto_light_client_update_block_lag_threshold: 3,
        auto_light_client_update_check_interval_secs: 1,
        confirmations: 1,
    };

    // Start hypernode in background task
    let hypernode_handle = devnet.join_set.spawn(async move {
        println!("Starting hypernode with light client update watchtower DISABLED");
        hypernode_args.run().await
    });

    // Give hypernode time to initialize
    sleep(Duration::from_secs(3)).await;

    // Mine blocks that would exceed the threshold
    let blocks_to_mine = 10;
    println!("Mining {} blocks (watchtower disabled)", blocks_to_mine);

    devnet
        .bitcoin
        .mine_blocks(blocks_to_mine)
        .await
        .expect("Failed to mine blocks");

    let new_bitcoin_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap() as u32;
    println!("New Bitcoin height: {}", new_bitcoin_height);

    // Wait a reasonable amount of time
    sleep(Duration::from_secs(10)).await;

    // Verify light client height has NOT been automatically updated
    let final_light_client_height = devnet
        .ethereum
        .rift_exchange_contract
        .lightClientHeight()
        .call()
        .await
        .unwrap();

    println!(
        "Final light client height: {} (should still be {})",
        final_light_client_height, initial_light_client_height
    );

    assert_eq!(
        final_light_client_height, initial_light_client_height,
        "Light client height should not change when watchtower is disabled"
    );

    let lag = new_bitcoin_height.saturating_sub(final_light_client_height);
    assert!(
        lag >= blocks_to_mine as u32,
        "Light client should be significantly behind Bitcoin tip when watchtower is disabled"
    );

    println!(
        "✅ Test passed: Light client remained at height {} while Bitcoin reached height {} (lag: {})",
        final_light_client_height, new_bitcoin_height, lag
    );

    // Clean shutdown
    hypernode_handle.abort();
}
