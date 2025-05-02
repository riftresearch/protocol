use alloy::{
    primitives::{utils::format_units, U256},
    providers::{ext::AnvilApi, ProviderBuilder, WsConnect},
    sol_types::SolEvent,
};
use bitcoin::{
    consensus::{Decodable, Encodable},
    hashes::Hash,
    Amount, Transaction,
};
use bitcoincore_rpc_async::RpcApi;
use data_engine::models::SwapStatus;
use devnet::RiftDevnet;
use hypernode::{HypernodeArgs, Provider};
use rift_core::vaults::SolidityHash;
use rift_sdk::{
    proof_generator::{ProofGeneratorType, RiftProofGenerator},
    txn_builder::{self, serialize_no_segwit, P2WPKHBitcoinWallet},
    DatabaseLocation,
};
use sol_bindings::{BaseCreateOrderParams, CreateOrderParams, OrdersUpdated};
use tokio::signal::{self, unix::signal};

use crate::test_utils::{create_deposit, setup_test_tracing, MultichainAccount};

#[tokio::test]
// Serial anything that uses alot of bitcoin mining
#[serial_test::serial]
async fn test_hypernode_simple_swap() {
    setup_test_tracing();
    // ---1) Spin up devnet with default config---

    let maker = MultichainAccount::new(1);
    let taker = MultichainAccount::new(2);

    println!(
        "Maker BTC P2WPKH: {:?}",
        maker.bitcoin_wallet.get_p2wpkh_script().to_hex_string()
    );
    println!(
        "Taker BTC P2WPKH: {:?}",
        taker.bitcoin_wallet.get_p2wpkh_script().to_hex_string()
    );
    println!("Maker BTC wallet: {:?}", maker.bitcoin_wallet.address);
    println!("Taker BTC wallet: {:?}", taker.bitcoin_wallet.address);
    println!("Maker EVM wallet: {:?}", maker.ethereum_address);
    println!("Taker EVM wallet: {:?}", taker.ethereum_address);

    // fund maker evm wallet, and taker btc wallet
    let (devnet, _funded_sats) = RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(maker.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
        .unwrap();

    let maker_evm_provider = ProviderBuilder::new()
        .wallet(maker.ethereum_wallet)
        .on_ws(WsConnect::new(devnet.ethereum.anvil.ws_endpoint_url()))
        .await
        .expect("Failed to create maker evm provider");

    // Quick references
    let rift_exchange = devnet.ethereum.rift_exchange_contract.clone();
    let token_contract = devnet.ethereum.token_contract.clone();

    // ---2) "Maker" address gets some ERC20 to deposit---

    println!("Maker address: {:?}", maker.ethereum_address);

    let deposit_amount = U256::from(100_000_000u128); //1 wrapped bitcoin
    let expected_sats = 100_000_000u64; // The maker wants 1 bitcoin for their 1 million tokens (1 BTC = 1 cbBTC token)

    let decimals = devnet
        .ethereum
        .token_contract
        .decimals()
        .call()
        .await
        .unwrap();

    println!(
        "Approving {} tokens to maker",
        format_units(deposit_amount, decimals).unwrap()
    );

    // Approve the RiftExchange to spend the maker's tokens
    let approve_call = token_contract.approve(*rift_exchange.address(), deposit_amount);
    maker_evm_provider
        .send_transaction(approve_call.into_transaction_request())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    println!("Approved");

    // ---3) Maker deposits liquidity into RiftExchange---
    // We'll fill in some "fake" deposit parameters.
    // This is just an example; in real usage you'd call e.g. depositLiquidity(...) with your chosen params.

    // We can skip real MMR proofs; for dev/test, we can pass dummy MMR proof data or a known "safe block."
    // For example, we'll craft a dummy "BlockLeaf" that the contract won't reject:
    let (safe_leaf, safe_siblings, safe_peaks) =
        devnet.contract_data_engine.get_tip_proof().await.unwrap();

    let mmr_root = devnet.contract_data_engine.get_mmr_root().await.unwrap();

    let safe_leaf: sol_bindings::BlockLeaf = safe_leaf.into();

    println!("Safe leaf tip (data engine): {:?}", safe_leaf);
    println!("Mmr root (data engine): {:?}", hex::encode(mmr_root));

    let light_client_height = devnet
        .ethereum
        .rift_exchange_contract
        .lightClientHeight()
        .call()
        .await
        .unwrap();

    let mmr_root = devnet
        .ethereum
        .rift_exchange_contract
        .mmrRoot()
        .call()
        .await
        .unwrap();

    println!("Light client height (queried): {:?}", light_client_height);
    println!("Mmr root (queried): {:?}", mmr_root);

    let maker_btc_wallet_script_pubkey = maker.bitcoin_wallet.get_p2wpkh_script();

    let padded_script = maker_btc_wallet_script_pubkey.to_bytes();

    let deposit_params = CreateOrderParams {
        base: BaseCreateOrderParams {
            owner: maker.ethereum_address,
            bitcoinScriptPubKey: padded_script.into(),
            salt: [0x44; 32].into(), // this can be anything
            confirmationBlocks: 2,   // require 2 confirmations (1 block to mine + 1 additional)
            // TODO: This is hellacious, remove the 3 different types for BlockLeaf somehow
            safeBlockLeaf: safe_leaf,
        },
        expectedSats: expected_sats,
        depositAmount: deposit_amount,
        designatedReceiver: taker.ethereum_address,
        safeBlockSiblings: safe_siblings.iter().map(From::from).collect(),
        safeBlockPeaks: safe_peaks.iter().map(From::from).collect(),
    };
    println!("Deposit params: {:?}", deposit_params);

    let deposit_call = rift_exchange.createOrder(deposit_params);

    let deposit_calldata = deposit_call.calldata();

    let deposit_transaction_request = deposit_call.clone().into_transaction_request();

    let deposit_tx = maker_evm_provider
        .send_transaction(deposit_transaction_request)
        .await;

    let receipt = match deposit_tx {
        Ok(tx) => {
            let receipt = tx.get_receipt().await.expect("No deposit tx receipt");
            println!("Deposit receipt: {:?}", receipt);
            receipt
        }
        Err(tx_error) => {
            println!("Deposit error: {:?}", tx_error);
            let block_height = devnet
                .ethereum
                .funded_provider
                .get_block_number()
                .await
                .map_err(|e| eyre::eyre!(e))
                .unwrap();

            let data = hex::encode(deposit_calldata);
            let from = maker.ethereum_address.to_string();
            let to = rift_exchange.address().to_string();
            println!(
                    "To debug failed proof broadcast run: cast call {} --from {} --data {} --trace --block {} --rpc-url {}",
                    to,
                    from,
                    data,
                    block_height,
                    devnet.ethereum.anvil.endpoint()
                );
            // contorl c pause here
            signal::ctrl_c().await.unwrap();
            panic!("Deposit failed");
        }
    };

    let receipt_logs = receipt.inner.logs();
    // this will have only a VaultsUpdated log
    let orders_updated_log = OrdersUpdated::decode_log(
        &receipt_logs
            .iter()
            .find(|log| *log.topic0().unwrap() == OrdersUpdated::SIGNATURE_HASH)
            .unwrap()
            .inner,
    )
    .unwrap();

    let new_order = &orders_updated_log.data.orders[0];

    println!("Created order: {:?}", new_order);

    // send double what we need so we have plenty to cover the fee
    let funding_amount = 200_000_000u64;

    // now send some bitcoin to the taker's btc address so we can get a UTXO to spend
    let funding_utxo = devnet
        .bitcoin
        .deal_bitcoin(
            taker.bitcoin_wallet.address.clone(),
            Amount::from_sat(funding_amount),
        ) // 1.5 bitcoin
        .await
        .unwrap();

    let txid = funding_utxo.txid;
    let wallet = taker.bitcoin_wallet;
    let fee_sats = 1000;
    let transaction = funding_utxo.transaction().unwrap();

    // if the predicate is true, we can spend it
    let txvout = transaction
        .output
        .iter()
        .enumerate()
        .find(|(_, output)| {
            output.script_pubkey.as_bytes() == wallet.get_p2wpkh_script().as_bytes()
                && output.value == Amount::from_sat(funding_amount)
        })
        .map(|(index, _)| index as u32)
        .unwrap();

    println!("Funding Transaction: {:?}", transaction);

    println!(
        "Funding UTXO: {:?}",
        hex::encode(&serialize_no_segwit(&transaction).unwrap())
    );

    let serialized = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&transaction);
    let mut reader = serialized.as_slice();
    let canon_bitcoin_tx = Transaction::consensus_decode_from_finite_reader(&mut reader).unwrap();
    let canon_txid = canon_bitcoin_tx.compute_txid();

    // ---4) Taker broadcasts a Bitcoin transaction paying that scriptPubKey---
    let payment_tx = txn_builder::build_rift_payment_transaction(
        &new_order,
        &canon_txid,
        &canon_bitcoin_tx,
        txvout,
        &wallet,
        fee_sats,
    )
    .unwrap();

    let payment_tx_serialized = &mut Vec::new();
    payment_tx.consensus_encode(payment_tx_serialized).unwrap();

    let payment_tx_serialized = payment_tx_serialized.as_slice();

    let current_block_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap();

    // broadcast it
    let broadcast_tx = devnet
        .bitcoin
        .rpc_client
        .send_raw_transaction(payment_tx_serialized)
        .await
        .unwrap();
    println!("Bitcoin tx sent");

    let payment_tx_id = payment_tx.compute_txid();
    let bitcoin_txid: [u8; 32] = payment_tx_id.as_raw_hash().to_byte_array();

    let swap_block_height = current_block_height + 1;

    // now mine enough blocks for confirmations (1 + 1 additional)
    devnet.bitcoin.mine_blocks(2).await.unwrap();

    let hypernode_account = MultichainAccount::new(2);

    devnet
        .ethereum
        .fund_eth_address(hypernode_account.ethereum_address, U256::MAX)
        .await
        .unwrap();

    let rpc_url_with_cookie = devnet.bitcoin.rpc_url_with_cookie.clone();
    let hypernode_handle = tokio::spawn(async move {
        let hypernode = HypernodeArgs {
            evm_ws_rpc: devnet.ethereum.anvil.ws_endpoint_url().to_string(),
            btc_rpc: rpc_url_with_cookie.clone(),
            private_key: hex::encode(hypernode_account.secret_bytes),
            checkpoint_file: devnet.checkpoint_file_path.clone(),
            database_location: DatabaseLocation::InMemory,
            rift_exchange_address: devnet.ethereum.rift_exchange_contract.address().to_string(),
            deploy_block_number: 0,
            btc_batch_rpc_size: 100,
            log_chunk_size: 10000,
            proof_generator: ProofGeneratorType::Execute,
        };
        hypernode.run().await.expect("Hypernode crashed");
    });

    println!(
        "Hypernode Bitcoin RPC URL: {:?}",
        devnet.bitcoin.rpc_url_with_cookie
    );
    let otc_swap = loop {
        let otc_swap = devnet
            .contract_data_engine
            .get_otc_swap_by_order_hash(new_order.hash())
            .await
            .unwrap();
        println!("OTCSwap: {:#?}", otc_swap);
        if otc_swap
            .clone()
            .is_some_and(|otc_swap| otc_swap.swap_status() == SwapStatus::ChallengePeriod)
        {
            break otc_swap.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };
    // Now warp ahead on the eth chain to the timestamp that unlocks the swap
    let swap_unlock_timestamp = otc_swap
        .payments
        .first()
        .unwrap()
        .payment
        .challengeExpiryTimestamp
        + 1;
    devnet
        .ethereum
        .funded_provider
        .anvil_set_time(swap_unlock_timestamp)
        .await
        .unwrap();

    devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(1), None)
        .await
        .unwrap();
    // now check again for ever until the swap is completed
    loop {
        let otc_swap = devnet
            .contract_data_engine
            .get_otc_swap_by_order_hash(new_order.hash())
            .await
            .unwrap();
        println!("OTCSwap Post Swap: {:#?}", otc_swap);
        if otc_swap.is_some_and(|otc_swap| otc_swap.swap_status() == SwapStatus::Completed) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    // stop the hypernode
    hypernode_handle.abort();
}

#[cfg(test)]
mod fork_watchtower_tests {
    use crate::test_utils::{create_deposit, setup_test_tracing, MultichainAccount};
    use alloy::providers::{DynProvider, ProviderBuilder, WsConnect};
    use alloy::rpc::json_rpc::ErrorPayload;
    use alloy::sol_types::SolError;
    use bitcoin_light_client_core::hasher::Keccak256Hasher;
    use bitcoin_light_client_core::leaves::BlockLeaf;
    use bitcoincore_rpc_async::RpcApi;
    use corepc_node::serde_json;
    use crypto_bigint::{CheckedAdd, Encoding};
    use hypernode::fork_watchtower::{ForkDetectionResult, ForkWatchtower};
    use hypernode::{HypernodeArgs, Provider};
    use rift_sdk::proof_generator::ProofGeneratorType;
    use rift_sdk::DatabaseLocation;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::time::timeout;

    use alloy::primitives::FixedBytes;
    use alloy::rpc::types::{Transaction, TransactionReceipt, TransactionRequest};
    use hypernode::txn_broadcast::{
        PreflightCheck, RevertInfo, TransactionExecutionResult, TransactionStatusUpdate,
    };
    use rift_core::giga::{RiftProgramInput, RustProofType};
    use sol_bindings::{BlockProofParams, RiftExchangeHarnessInstance};
    use tokio::sync::broadcast;

    use serde_json::value::RawValue;
    use sol_bindings::{
        BlockNotConfirmed, BlockNotInChain, ChainworkTooLow, CheckpointNotEstablished,
    };

    /// Tests that the fork watchtower correctly identifies when there is no fork
    #[tokio::test]
    #[serial_test::serial]
    async fn test_fork_watchtower_no_fork_detection() {
        setup_test_tracing();

        let (devnet, rift_exchange, _, maker, transaction_broadcaster) = create_deposit(true).await;

        let btc_rpc = devnet.bitcoin.rpc_client.clone();
        let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
        let contract_data_engine = devnet.contract_data_engine.clone();

        // Detect fork
        let detection_result =
            ForkWatchtower::detect_fork(&contract_data_engine, &bitcoin_data_engine, &btc_rpc, 100)
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
    #[serial_test::serial]
    async fn test_fork_watchtower_stale_chain_detection() {
        setup_test_tracing();

        let (mut devnet, rift_exchange, _, maker, transaction_broadcaster) =
            create_deposit(true).await;

        let bitcoin_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap();
        println!("Initial Bitcoin height: {}", bitcoin_height);

        let btc_rpc = devnet.bitcoin.rpc_client.clone();
        let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
        let contract_data_engine = devnet.contract_data_engine.clone();

        // Force the light client to be stale by mining blocks but keeping the light client at the old height and ensuring its still a valid subchain
        let initial_mmr_root = contract_data_engine.get_mmr_root().await.unwrap();
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
            ForkWatchtower::detect_fork(&contract_data_engine, &bitcoin_data_engine, &btc_rpc, 100)
                .await
                .expect("Fork detection after mining failed");

        // Check we got stale chain
        match detection_result {
            ForkDetectionResult::StaleChain => {
                println!("detected stale chain");

                // Verify the light client tip is still included in the bde chain
                let light_client_tip_index = contract_data_engine
                    .checkpointed_block_tree
                    .read()
                    .await
                    .get_leaf_count()
                    .await
                    .unwrap()
                    - 1;
                let light_client_tip = contract_data_engine
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
    #[serial_test::serial]
    async fn test_fork_watchtower_error_handling() {
        setup_test_tracing();

        let create_raw_value = |hex_data: &[u8]| -> Option<Box<RawValue>> {
            let hex_string = format!("\"0x{}\"", hex::encode(hex_data));
            RawValue::from_string(hex_string).ok()
        };

        let chainwork_too_low_revert = hypernode::txn_broadcast::RevertInfo {
            error_payload: ErrorPayload {
                code: 3,
                message: "execution reverted: ChainworkTooLow".to_string().into(),
                data: create_raw_value(&ChainworkTooLow::SELECTOR),
            },
            debug_cli_command: "cast...".to_string(),
        };

        let should_retry =
            ForkWatchtower::handle_transaction_revert(&chainwork_too_low_revert);
        assert!(
            !should_retry,
            "Dont retry when ChainworkTooLow error occurs"
        );

        let checkpoint_not_established_revert = hypernode::txn_broadcast::RevertInfo {
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
    #[serial_test::serial]
    async fn test_fork_watchtower_fork_detection_and_resolution() {
        setup_test_tracing();

        let (mut devnet, rift_exchange, _, maker, transaction_broadcaster) =
            create_deposit(true).await;

        let btc_rpc = devnet.bitcoin.rpc_client.clone();
        let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
        let contract_data_engine = devnet.contract_data_engine.clone();

        // Make sure both chains are in sync meaning no fork
        let initial_result =
            ForkWatchtower::detect_fork(&contract_data_engine, &bitcoin_data_engine, &btc_rpc, 100)
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

        let light_client_tip_index = contract_data_engine
            .checkpointed_block_tree
            .read()
            .await
            .get_leaf_count()
            .await
            .unwrap()
            - 1;

        let current_light_client_tip = contract_data_engine
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

        let mut chainwork = current_light_client_tip.chainwork_as_u256();

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
            let mut checkpointed_block_tree =
                contract_data_engine.checkpointed_block_tree.write().await;

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

            contract_data_engine
                .update_mmr_root(new_root)
                .await
                .unwrap();
        }

        let updated_light_client_tip_index = contract_data_engine
            .checkpointed_block_tree
            .read()
            .await
            .get_leaf_count()
            .await
            .unwrap()
            - 1;

        let updated_light_client_tip = contract_data_engine
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
            ForkWatchtower::detect_fork(&contract_data_engine, &bitcoin_data_engine, &btc_rpc, 100)
                .await
                .expect("Fork detection after mining failed");

        println!("Fork detection result: {:?}", detection_result);

        match detection_result {
            ForkDetectionResult::ForkDetected(chain_transition) => {
                println!("detected fork");

                assert!(
                    chain_transition.new_headers.len() > 0,
                    "Chain transition should have new headers"
                );
                assert_eq!(
                    chain_transition.current_mmr_root,
                    contract_data_engine.get_mmr_root().await.unwrap(),
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
                let initial_light_client_mmr_root =
                    contract_data_engine.get_mmr_root().await.unwrap();
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

                contract_data_engine
                    .reset_mmr_for_testing(&bde_leaves)
                    .await
                    .expect("Failed to reset light client MMR");

                let final_light_client_mmr_root =
                    contract_data_engine.get_mmr_root().await.unwrap();

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
                let current_leaf_count = contract_data_engine
                    .checkpointed_block_tree
                    .read()
                    .await
                    .get_leaf_count()
                    .await
                    .unwrap();

                for i in 0..current_leaf_count {
                    let leaf_opt = contract_data_engine
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
    #[serial_test::serial]
    async fn test_fork_watchtower_light_client_tip_not_in_bde() {
        setup_test_tracing();

        let (mut devnet, rift_exchange, _, maker, transaction_broadcaster) =
            create_deposit(true).await;

        let btc_rpc = devnet.bitcoin.rpc_client.clone();
        let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
        let contract_data_engine = devnet.contract_data_engine.clone();

        // make sure both chains are in sync so no fork
        let initial_result =
            ForkWatchtower::detect_fork(&contract_data_engine, &bitcoin_data_engine, &btc_rpc, 100)
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

        let light_client_tip_index = contract_data_engine
            .checkpointed_block_tree
            .read()
            .await
            .get_leaf_count()
            .await
            .unwrap()
            - 1;

        let current_light_client_tip = contract_data_engine
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
            let mut checkpointed_block_tree =
                contract_data_engine.checkpointed_block_tree.write().await;

            let root = checkpointed_block_tree.get_root().await.unwrap();

            checkpointed_block_tree
                .update_from_checkpoint(&root, &[fake_block_leaf])
                .await
                .expect("Failed to update light client with fake block");

            let new_root = checkpointed_block_tree.get_root().await.unwrap();

            // update the cde root cache with the new root
            drop(checkpointed_block_tree);

            // Update the cde cached MMR root
            contract_data_engine
                .update_mmr_root(new_root)
                .await
                .unwrap();
        }

        // Verify the light client has been updated with fake block
        let new_light_client_tip_index = contract_data_engine
            .checkpointed_block_tree
            .read()
            .await
            .get_leaf_count()
            .await
            .unwrap()
            - 1;

        let new_light_client_tip = contract_data_engine
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
        let is_included = ForkWatchtower::check_leaf_inclusion_in_bde(
            &new_light_client_tip,
            &bitcoin_mmr,
            &btc_rpc,
        )
        .await
        .expect("Failed to check leaf inclusion");

        assert!(
            !is_included,
            "Light client tip should not be included in BDE chain for this test"
        );

        println!("Detecting fork with light client tip not in BDE chain");
        let detection_result =
            ForkWatchtower::detect_fork(&contract_data_engine, &bitcoin_data_engine, &btc_rpc, 100)
                .await
                .expect("Fork detection failed");

        // we should have a fork
        match detection_result {
            ForkDetectionResult::ForkDetected(chain_transition) => {
                println!("detected fork, light client tip not in BDE chain");

                assert!(
                    chain_transition.new_headers.len() > 0,
                    "Chain transition should have new headers"
                );
                assert_eq!(
                    chain_transition.current_mmr_root,
                    contract_data_engine.get_mmr_root().await.unwrap(),
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

                let (public_values, _) = rift_program_input.get_auxiliary_light_client_data();

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
    #[serial_test::serial]
    async fn test_fork_watchtower_equal_chainwork() {
        setup_test_tracing();

        let (mut devnet, rift_exchange, _, maker, transaction_broadcaster) =
            create_deposit(true).await;

        let btc_rpc = devnet.bitcoin.rpc_client.clone();
        let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
        let contract_data_engine = devnet.contract_data_engine.clone();

        let light_client_tip_index = contract_data_engine
            .checkpointed_block_tree
            .read()
            .await
            .get_leaf_count()
            .await
            .unwrap()
            - 1;

        let light_client_tip = contract_data_engine
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
            ForkWatchtower::detect_fork(&contract_data_engine, &bitcoin_data_engine, &btc_rpc, 100)
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
}
