use crate::test_utils::create_deposit;
use alloy::rpc::json_rpc::ErrorPayload;
use alloy::sol_types::SolError;
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::RpcApi;
use corepc_node::serde_json;
use crypto_bigint::{CheckedAdd, Encoding};
use hypernode::fork_watchtower::{ForkDetectionResult, ForkWatchtower};
use std::time::Duration;

use tokio::time::timeout;

use serde_json::value::RawValue;
use sol_bindings::{ChainworkTooLow, CheckpointNotEstablished};

/// Tests that the fork watchtower correctly identifies when there is no fork
#[tokio::test]
async fn test_fork_watchtower_no_fork_detection() {
    let (devnet, _rift_exchange, _, _maker, _transaction_broadcaster) = create_deposit(true).await;

    let btc_rpc = devnet.bitcoin.rpc_client.clone();
    let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
    let rift_indexer = devnet.rift_indexer.clone();

    // Detect fork
    let detection_result =
        ForkWatchtower::detect_fork(&rift_indexer, &bitcoin_data_engine, &btc_rpc, 100)
            .await
            .expect("Fork detection failed");

    // Verify result is NoFork
    match detection_result {
        ForkDetectionResult::NoFork => {
            println!("detected no fork");
        }
        other => {
            panic!("Expected NoFork, got {:?}", other);
        }
    }
}

/// Tests that the fork watchtower correctly identifies a stale chain
#[tokio::test]
async fn test_fork_watchtower_stale_chain_detection() {
    let (devnet, _rift_exchange, _, _maker, _transaction_broadcaster) = create_deposit(true).await;

    let bitcoin_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap();
    println!("Initial Bitcoin height: {}", bitcoin_height);

    let btc_rpc = devnet.bitcoin.rpc_client.clone();
    let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
    let rift_indexer = devnet.rift_indexer.clone();

    // Force the light client to be stale by mining blocks but keeping the light client at the old height and ensuring its still a valid subchain
    let initial_mmr_root = rift_indexer.get_mmr_root().await.unwrap();
    println!(
        "Initial light client MMR root: {}",
        hex::encode(initial_mmr_root)
    );

    devnet
        .bitcoin
        .mine_blocks(3)
        .await
        .expect("Failed to mine blocks");

    // Wait for the bde to sync the new blocks
    let mut block_subscription = devnet.bitcoin.data_engine.subscribe_to_new_blocks();
    let timeout_duration = Duration::from_secs(20);

    let blocks_result = timeout(timeout_duration, async {
        for i in 0..3 {
            if let Ok(block) = block_subscription.recv().await {
                println!(
                    "Received block #{}: height={}, hash={}",
                    i + 1,
                    block.height,
                    hex::encode(block.block_hash)
                );
            }
        }
    })
    .await;

    if blocks_result.is_err() {
        println!("Err from blocks_result: Timed out waiting for blocks, continue");
    }

    let detection_result =
        ForkWatchtower::detect_fork(&rift_indexer, &bitcoin_data_engine, &btc_rpc, 100)
            .await
            .expect("Fork detection after mining failed");

    // Check we got stale chain
    match detection_result {
        ForkDetectionResult::StaleChain => {
            println!("detected stale chain");

            // Verify the light client tip is still included in the bde chain
            let light_client_tip_index = rift_indexer
                .checkpointed_block_tree
                .read()
                .await
                .get_leaf_count()
                .await
                .unwrap()
                - 1;
            let light_client_tip = rift_indexer
                .checkpointed_block_tree
                .read()
                .await
                .get_leaf_by_leaf_index(light_client_tip_index)
                .await
                .unwrap()
                .unwrap();

            let bitcoin_mmr = bitcoin_data_engine.indexed_mmr.read().await;

            let is_included = ForkWatchtower::check_leaf_inclusion_in_bde(
                &light_client_tip,
                &bitcoin_mmr,
                &btc_rpc,
            )
            .await
            .expect("Leaf inclusion check failed");

            assert!(
                is_included,
                "Light client tip should be included in BDE chain"
            );
        }
        other => {
            panic!("Expected StaleChain, got {:?}", other);
        }
    }
}

/// Tests that the fork watchtower correctly handles error conditions
#[tokio::test]
async fn test_fork_watchtower_error_handling() {
    let create_raw_value = |hex_data: &[u8]| -> Option<Box<RawValue>> {
        let hex_string = format!("\"0x{}\"", hex::encode(hex_data));
        RawValue::from_string(hex_string).ok()
    };

    let chainwork_too_low_revert = rift_sdk::txn_broadcast::RevertInfo {
        error_payload: ErrorPayload {
            code: 3,
            message: "execution reverted: ChainworkTooLow".to_string().into(),
            data: create_raw_value(&ChainworkTooLow::SELECTOR),
        },
        debug_cli_command: "cast...".to_string(),
    };

    let should_retry = ForkWatchtower::handle_transaction_revert(&chainwork_too_low_revert);
    assert!(
        !should_retry,
        "Dont retry when ChainworkTooLow error occurs"
    );

    let checkpoint_not_established_revert = rift_sdk::txn_broadcast::RevertInfo {
        error_payload: ErrorPayload {
            code: 3,
            message: "execution reverted: CheckpointNotEstablished"
                .to_string()
                .into(),
            data: create_raw_value(&CheckpointNotEstablished::SELECTOR),
        },
        debug_cli_command: "cast...".to_string(),
    };

    let should_retry =
        ForkWatchtower::handle_transaction_revert(&checkpoint_not_established_revert);
    assert!(
        !should_retry,
        "Dont retry when CheckpointNotEstablished error occurs"
    );
}

/// Tests that the fork watchtower correctly detects and resolves a simulated fork
#[tokio::test]
async fn test_fork_watchtower_fork_detection_and_resolution() {
    let (devnet, _rift_exchange, _, _maker, _transaction_broadcaster) = create_deposit(true).await;

    let btc_rpc = devnet.bitcoin.rpc_client.clone();
    let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
    let rift_indexer = devnet.rift_indexer.clone();

    // Make sure both chains are in sync meaning no fork
    let initial_result =
        ForkWatchtower::detect_fork(&rift_indexer, &bitcoin_data_engine, &btc_rpc, 100)
            .await
            .expect("Initial fork detection failed");

    match initial_result {
        ForkDetectionResult::NoFork => {
            println!("verified initial state has no fork");
        }
        other => {
            panic!("Expected NoFork in initial state, got {:?}", other);
        }
    }

    println!("Creating a simulated fork by mining Bitcoin blocks");
    devnet
        .bitcoin
        .mine_blocks(5)
        .await
        .expect("Failed to mine blocks");

    // Wait for the Bitcoin data engine to sync the new blocks
    let mut block_subscription = bitcoin_data_engine.subscribe_to_new_blocks();
    let mut blocks_seen = 0;
    let timeout_duration = Duration::from_secs(30);

    let blocks_result = timeout(timeout_duration, async {
        while blocks_seen < 5 {
            if let Ok(block) = block_subscription.recv().await {
                blocks_seen += 1;
                println!("Received block at height {}", block.height);
            }
        }
    })
    .await;

    if blocks_result.is_err() {
        println!("Err from blocks_result: Timed out waiting for all blocks, continue");
    }

    let light_client_tip_index = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_count()
        .await
        .unwrap()
        - 1;

    let current_light_client_tip = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_by_leaf_index(light_client_tip_index)
        .await
        .unwrap()
        .unwrap();

    let bitcoin_tip_index = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_count()
        .await
        .unwrap()
        - 1;

    let bitcoin_tip = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_by_leaf_index(bitcoin_tip_index)
        .await
        .unwrap()
        .unwrap();

    println!(
        "Current light client tip: height={}, hash={}",
        current_light_client_tip.height,
        hex::encode(current_light_client_tip.block_hash)
    );

    println!(
        "Current bitcoin tip: height={}, hash={}",
        bitcoin_tip.height,
        hex::encode(bitcoin_tip.block_hash)
    );

    // Create a fake block with a invalid hash
    let fake_block_hash = [0xFF; 32];

    let chainwork = current_light_client_tip.chainwork_as_u256();

    let one = crypto_bigint::U256::from_u8(1);
    let fake_chainwork = chainwork.checked_add(&one).unwrap();

    // Make sure the height is higher than current tip
    let fake_block_leaf = BlockLeaf {
        block_hash: fake_block_hash,
        height: current_light_client_tip.height + 1,
        cumulative_chainwork: fake_chainwork.to_be_bytes(),
    };

    println!(
        "Created fake block: height={}, hash={}",
        fake_block_leaf.height,
        hex::encode(fake_block_leaf.block_hash)
    );

    // append the fake block to the lc chain
    {
        let mut checkpointed_block_tree = rift_indexer.checkpointed_block_tree.write().await;

        let root = checkpointed_block_tree.get_root().await.unwrap();

        println!(
            "Light client MMR root before adding fake block: {}",
            hex::encode(root)
        );

        checkpointed_block_tree
            .update_from_checkpoint(&root, &[fake_block_leaf])
            .await
            .expect("Failed to update light client with fake block");

        let new_root = checkpointed_block_tree.get_root().await.unwrap();

        println!(
            "Light client MMR root after adding fake block: {}",
            hex::encode(new_root)
        );

        // Update the cde root cache with the new root
        drop(checkpointed_block_tree);

        rift_indexer.update_mmr_root(new_root).await.unwrap();
    }

    let updated_light_client_tip_index = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_count()
        .await
        .unwrap()
        - 1;

    let updated_light_client_tip = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_by_leaf_index(updated_light_client_tip_index)
        .await
        .unwrap()
        .unwrap();

    println!(
        "Updated light client tip: height={}, hash={}",
        updated_light_client_tip.height,
        hex::encode(updated_light_client_tip.block_hash)
    );

    assert_eq!(
        updated_light_client_tip.block_hash, fake_block_hash,
        "Light client tip should be the fake block"
    );

    {
        let bitcoin_mmr = bitcoin_data_engine.indexed_mmr.read().await;
        let is_included = ForkWatchtower::check_leaf_inclusion_in_bde(
            &updated_light_client_tip,
            &bitcoin_mmr,
            &btc_rpc,
        )
        .await
        .expect("Failed to check leaf inclusion");

        println!("Is fake block included in BDE chain? {}", is_included);

        assert!(
            !is_included,
            "Fake block should not be included in BDE chain"
        );
    }

    // detect the fork
    println!("Detecting fork after mining blocks");
    let detection_result =
        ForkWatchtower::detect_fork(&rift_indexer, &bitcoin_data_engine, &btc_rpc, 100)
            .await
            .expect("Fork detection after mining failed");

    println!("Fork detection result: {:?}", detection_result);

    match detection_result {
        ForkDetectionResult::ForkDetected(chain_transition) => {
            println!("detected fork");

            assert!(
                !chain_transition.new_headers.is_empty(),
                "Chain transition should have new headers"
            );
            assert_eq!(
                chain_transition.current_mmr_root,
                rift_indexer.get_mmr_root().await.unwrap(),
                "Chain transition current_mmr_root should match contract data engine root"
            );

            let fake_block_hash_in_keccak = fake_block_leaf.hash::<Keccak256Hasher>();
            let contains_fake_hash = chain_transition
                .disposed_leaf_hashes
                .iter()
                .any(|hash| *hash == fake_block_hash_in_keccak);

            assert!(
                contains_fake_hash,
                "Disposed leaf hashes should include the fake block"
            );

            // Get the initial state
            let initial_light_client_mmr_root = rift_indexer.get_mmr_root().await.unwrap();
            let bde_mmr_root = bitcoin_data_engine
                .indexed_mmr
                .read()
                .await
                .get_root()
                .await
                .unwrap();

            println!(
                "Initial light client MMR root: {}",
                hex::encode(initial_light_client_mmr_root)
            );
            println!("Initial BDE MMR root: {}", hex::encode(bde_mmr_root));

            // Get all leaves from BDE
            let bde_leaf_count = bitcoin_data_engine
                .indexed_mmr
                .read()
                .await
                .get_leaf_count()
                .await
                .unwrap();

            let mut bde_leaves = Vec::with_capacity(bde_leaf_count);
            for i in 0..bde_leaf_count {
                if let Some(leaf) = bitcoin_data_engine
                    .indexed_mmr
                    .read()
                    .await
                    .get_leaf_by_leaf_index(i)
                    .await
                    .unwrap()
                {
                    bde_leaves.push(leaf);
                }
            }

            println!("Simulating fork resolution by replacing light client chain");

            rift_indexer
                .reset_mmr_for_testing(&bde_leaves)
                .await
                .expect("Failed to reset light client MMR");

            let final_light_client_mmr_root = rift_indexer.get_mmr_root().await.unwrap();

            println!(
                "Final light client MMR root: {}",
                hex::encode(final_light_client_mmr_root)
            );
            println!("Final BDE MMR root: {}", hex::encode(bde_mmr_root));

            assert_eq!(
                final_light_client_mmr_root, bde_mmr_root,
                "Light client MMR root should match BDE MMR root after fork resolution"
            );

            let mut found_fake_block = false;
            let current_leaf_count = rift_indexer
                .checkpointed_block_tree
                .read()
                .await
                .get_leaf_count()
                .await
                .unwrap();

            for i in 0..current_leaf_count {
                let leaf_opt = rift_indexer
                    .checkpointed_block_tree
                    .read()
                    .await
                    .get_leaf_by_leaf_index(i)
                    .await
                    .unwrap();

                if let Some(leaf) = leaf_opt {
                    if leaf.block_hash == fake_block_hash {
                        found_fake_block = true;
                        break;
                    }
                }
            }

            assert!(
                !found_fake_block,
                "Fake block should have been removed from the light client chain"
            );

            println!("verified fake block has been removed from light client chain");
        }
        other => {
            panic!("Expected ForkDetected, got {:?}", other);
        }
    }
}

#[tokio::test]
async fn test_fork_watchtower_light_client_tip_not_in_bde() {
    let (devnet, _rift_exchange, _, _maker, _transaction_broadcaster) = create_deposit(true).await;

    let btc_rpc = devnet.bitcoin.rpc_client.clone();
    let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
    let rift_indexer = devnet.rift_indexer.clone();

    // make sure both chains are in sync so no fork
    let initial_result =
        ForkWatchtower::detect_fork(&rift_indexer, &bitcoin_data_engine, &btc_rpc, 100)
            .await
            .expect("Initial fork detection failed");

    match initial_result {
        ForkDetectionResult::NoFork => {
            println!("verified initial state has no fork");
        }
        other => {
            panic!("Expected NoFork in initial state, got {:?}", other);
        }
    }

    // Mine a block in Bitcoin chain and wait for the BDE to catch up so that the real chain is ahead of the light client
    println!("Mining 3 blocks");
    devnet
        .bitcoin
        .mine_blocks(3)
        .await
        .expect("Failed to mine 3 blocks");

    // Wait for BDE to sync
    let mut block_subscription = bitcoin_data_engine.subscribe_to_new_blocks();
    for _ in 0..3 {
        let _ = block_subscription.recv().await;
    }

    // Create divergent chain

    let light_client_tip_index = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_count()
        .await
        .unwrap()
        - 1;

    let current_light_client_tip = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_by_leaf_index(light_client_tip_index)
        .await
        .unwrap()
        .unwrap();

    println!(
        "Current light client tip: height={}, hash={}",
        current_light_client_tip.height,
        hex::encode(current_light_client_tip.block_hash)
    );

    let bitcoin_tip_index = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_count()
        .await
        .unwrap()
        - 1;

    let bitcoin_tip = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_by_leaf_index(bitcoin_tip_index)
        .await
        .unwrap()
        .unwrap();

    println!(
        "Current BDE tip: height={}, hash={}",
        bitcoin_tip.height,
        hex::encode(bitcoin_tip.block_hash)
    );

    // Create a fake block leaf that doesnt exist in the BDE chain
    let fake_block_hash = [0x42; 32];
    let fake_chainwork = current_light_client_tip.chainwork_as_u256();
    let fake_block_leaf = BlockLeaf {
        block_hash: fake_block_hash,
        height: current_light_client_tip.height + 1,
        cumulative_chainwork: fake_chainwork.to_be_bytes(),
    };

    println!(
        "Created fake block: height={}, hash={}",
        fake_block_leaf.height,
        hex::encode(fake_block_leaf.block_hash)
    );

    {
        let mut checkpointed_block_tree = rift_indexer.checkpointed_block_tree.write().await;

        let root = checkpointed_block_tree.get_root().await.unwrap();

        checkpointed_block_tree
            .update_from_checkpoint(&root, &[fake_block_leaf])
            .await
            .expect("Failed to update light client with fake block");

        let new_root = checkpointed_block_tree.get_root().await.unwrap();

        // update the cde root cache with the new root
        drop(checkpointed_block_tree);

        // Update the cde cached MMR root
        rift_indexer.update_mmr_root(new_root).await.unwrap();
    }

    // Verify the light client has been updated with fake block
    let new_light_client_tip_index = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_count()
        .await
        .unwrap()
        - 1;

    let new_light_client_tip = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_by_leaf_index(new_light_client_tip_index)
        .await
        .unwrap()
        .unwrap();

    println!(
        "New light client tip: height={}, hash={}",
        new_light_client_tip.height,
        hex::encode(new_light_client_tip.block_hash)
    );

    // Verify the light client tip has changed to fake block
    assert_eq!(
        new_light_client_tip.block_hash, fake_block_hash,
        "Light client tip should be the fake block"
    );

    // use the check_leaf_inclusion_in_bde method to check the lc tip is not in bde chain
    let bitcoin_mmr = bitcoin_data_engine.indexed_mmr.read().await;
    let is_included =
        ForkWatchtower::check_leaf_inclusion_in_bde(&new_light_client_tip, &bitcoin_mmr, &btc_rpc)
            .await
            .expect("Failed to check leaf inclusion");

    assert!(
        !is_included,
        "Light client tip should not be included in BDE chain for this test"
    );

    println!("Detecting fork with light client tip not in BDE chain");
    let detection_result =
        ForkWatchtower::detect_fork(&rift_indexer, &bitcoin_data_engine, &btc_rpc, 100)
            .await
            .expect("Fork detection failed");

    // we should have a fork
    match detection_result {
        ForkDetectionResult::ForkDetected(chain_transition) => {
            println!("detected fork, light client tip not in BDE chain");

            assert!(
                !chain_transition.new_headers.is_empty(),
                "Chain transition should have new headers"
            );
            assert_eq!(
                chain_transition.current_mmr_root,
                rift_indexer.get_mmr_root().await.unwrap(),
                "Chain transition current_mmr_root should match contract data engine root"
            );

            assert!(
                !chain_transition.disposed_leaf_hashes.is_empty(),
                "Chain transition should have disposed leaf hashes"
            );

            let light_client_tip_hash = new_light_client_tip.hash::<Keccak256Hasher>();
            let contains_tip_hash = chain_transition
                .disposed_leaf_hashes
                .iter()
                .any(|hash| *hash == light_client_tip_hash);

            assert!(
                contains_tip_hash,
                "Disposed leaf hashes should include the light client tip"
            );

            let rift_program_input = rift_core::giga::RiftProgramInput::builder()
                .proof_type(rift_core::giga::RustProofType::LightClientOnly)
                .light_client_input(chain_transition.clone())
                .build()
                .expect("Failed to build rift program input");

            let (public_values, _) = rift_program_input
                .get_auxiliary_light_client_data()
                .unwrap();

            assert_ne!(
                public_values.priorMmrRoot, public_values.newMmrRoot,
                "New MMR root should be different from prior MMR root"
            );

            assert!(
                public_values.tipBlockLeaf.height >= bitcoin_tip.height,
                "Tip block leaf height should be at least as high as Bitcoin tip height"
            );
        }
        other => {
            panic!(
                "Expected ForkDetected (light client tip not in BDE), got {:?}",
                other
            );
        }
    }
}

#[tokio::test]
async fn test_fork_watchtower_equal_chainwork() {
    let (devnet, _rift_exchange, _, _maker, _transaction_broadcaster) = create_deposit(true).await;

    let btc_rpc = devnet.bitcoin.rpc_client.clone();
    let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
    let rift_indexer = devnet.rift_indexer.clone();

    let light_client_tip_index = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_count()
        .await
        .unwrap()
        - 1;

    let light_client_tip = rift_indexer
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_by_leaf_index(light_client_tip_index)
        .await
        .unwrap()
        .unwrap();

    println!(
        "Light client tip: height={}, hash={}, chainwork={}",
        light_client_tip.height,
        hex::encode(light_client_tip.block_hash),
        hex::encode(light_client_tip.cumulative_chainwork)
    );

    // Create a alt block with the same chainwork but a diff hash to test the first seen policy
    let alt_block_hash = [0xAA; 32];
    let alt_block_leaf = BlockLeaf {
        block_hash: alt_block_hash,
        height: light_client_tip.height + 1,
        cumulative_chainwork: light_client_tip.cumulative_chainwork,
    };

    println!(
        "Created alternative block with equal chainwork: height={}, hash={}, chainwork={}",
        alt_block_leaf.height,
        hex::encode(alt_block_leaf.block_hash),
        hex::encode(alt_block_leaf.cumulative_chainwork)
    );

    // Update the BDE chain with the alt block
    {
        let mut bitcoin_mmr = bitcoin_data_engine.indexed_mmr.write().await;
        bitcoin_mmr
            .append(&alt_block_leaf)
            .await
            .expect("Failed to append alternative block to BDE");
    }

    // check to see that the BDE now has the alt block
    let bitcoin_tip_index = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_count()
        .await
        .unwrap()
        - 1;

    let bitcoin_tip = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_by_leaf_index(bitcoin_tip_index)
        .await
        .unwrap()
        .unwrap();

    println!(
        "BDE tip after adding alternative block: height={}, hash={}, chainwork={}",
        bitcoin_tip.height,
        hex::encode(bitcoin_tip.block_hash),
        hex::encode(bitcoin_tip.cumulative_chainwork)
    );

    // Verify the BDE and light client both have blocks with equal chainwork
    let light_client_chainwork = light_client_tip.chainwork_as_u256();
    let bde_chainwork = bitcoin_tip.chainwork_as_u256();

    assert_eq!(
        light_client_chainwork, bde_chainwork,
        "BDE and light client should have equal chainwork for this test"
    );

    // Run fork detection should follow first seen policy
    println!("Detecting fork with equal chainwork blocks (first-seen policy)");
    let detection_result =
        ForkWatchtower::detect_fork(&rift_indexer, &bitcoin_data_engine, &btc_rpc, 100)
            .await
            .expect("Fork detection failed");

    match detection_result {
        ForkDetectionResult::NoFork => {
            println!("applied first-seen policy for equal chainwork");
        }
        other => {
            panic!(
                "Expected NoFork with equal chainwork, first seen policy, got {:?}",
                other
            );
        }
    }
}
