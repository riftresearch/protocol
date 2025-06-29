use alloy::{
    primitives::{utils::format_units, U256},
    providers::ext::AnvilApi,
    sol_types::SolEvent,
};
use bitcoin::{
    consensus::{Decodable, Encodable},
    hashes::Hash,
    Amount, Transaction,
};
use bitcoincore_rpc_async::RpcApi;
use devnet::RiftDevnet;
use hypernode::{HypernodeArgs, Provider};
use rift_indexer::models::SwapStatus;
use rift_sdk::{
    create_websocket_wallet_provider,
    proof_generator::ProofGeneratorType,
    txn_builder::{self, serialize_no_segwit},
    DatabaseLocation, MultichainAccount,
};
use sol_bindings::{BaseCreateOrderParams, CreateOrderParams, OrderCreated};
use tokio::signal::{self};

#[tokio::test]
// Serial anything that uses alot of bitcoin mining
async fn test_hypernode_simple_swap() {
    // ---1) Spin up devnet with default config---

    let maker = MultichainAccount::new(1);
    let taker = MultichainAccount::new(2);
    let maker2 = MultichainAccount::new(3); // Second maker for second swap

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
    println!("Maker2 EVM wallet: {:?}", maker2.ethereum_address);

    // fund maker evm wallet, and taker btc wallet
    let (devnet, _funded_sats) = RiftDevnet::builder()
        .funded_evm_address(maker.ethereum_address.to_string())
        .funded_evm_address(maker2.ethereum_address.to_string())
        .build()
        .await
        .expect("Failed to build devnet");

    // Easier if we just mine automatically
    devnet
        .ethereum
        .funded_provider
        .anvil_set_interval_mining(1)
        .await
        .unwrap();

    let maker_evm_provider = create_websocket_wallet_provider(
        devnet.ethereum.anvil.ws_endpoint_url().to_string().as_str(),
        maker.secret_bytes,
    )
    .await
    .expect("Failed to create maker evm provider");

    let maker2_evm_provider = create_websocket_wallet_provider(
        devnet.ethereum.anvil.ws_endpoint_url().to_string().as_str(),
        maker2.secret_bytes,
    )
    .await
    .expect("Failed to create maker2 evm provider");

    // Quick references
    let rift_exchange = devnet.ethereum.rift_exchange_contract.clone();
    let token_contract = devnet.ethereum.token_contract.clone();

    // ---2) First Swap: Maker1 creates order, taker pays with Bitcoin---

    println!("=== FIRST SWAP ===");
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
    let (safe_leaf, safe_siblings, safe_peaks) = devnet.rift_indexer.get_tip_proof().await.unwrap();

    let mmr_root = devnet.rift_indexer.get_mmr_root().await.unwrap();

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
    let order_created_log = OrderCreated::decode_log(
        &receipt_logs
            .iter()
            .find(|log| *log.topic0().unwrap() == OrderCreated::SIGNATURE_HASH)
            .unwrap()
            .inner,
    )
    .unwrap();

    let new_order = &order_created_log.data.order;

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

    let _txid = funding_utxo.txid;
    let wallet = &taker.bitcoin_wallet;
    let fee_sats = 1000;
    let transaction: Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&funding_utxo.hex).unwrap()).unwrap();

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
        hex::encode(serialize_no_segwit(&transaction).unwrap())
    );

    let serialized = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&transaction);
    let mut reader = serialized.as_slice();
    let canon_bitcoin_tx = Transaction::consensus_decode_from_finite_reader(&mut reader).unwrap();
    let canon_txid = canon_bitcoin_tx.compute_txid();

    // ---4) Taker broadcasts a Bitcoin transaction paying that scriptPubKey---
    let payment_tx = txn_builder::build_rift_payment_transaction_single_input(
        &vec![new_order.clone()],
        &canon_txid,
        &canon_bitcoin_tx,
        txvout,
        wallet,
        fee_sats,
    )
    .unwrap();

    let payment_tx_serialized = &mut Vec::new();
    payment_tx.consensus_encode(payment_tx_serialized).unwrap();

    let payment_tx_serialized = payment_tx_serialized.as_slice();

    let current_block_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap();

    // broadcast it
    let _broadcast_tx = devnet
        .bitcoin
        .rpc_client
        .send_raw_transaction(payment_tx_serialized)
        .await
        .unwrap();
    println!("Bitcoin tx sent");

    let payment_tx_id = payment_tx.compute_txid();
    let _bitcoin_txid: [u8; 32] = payment_tx_id.as_raw_hash().to_byte_array();

    let _swap_block_height = current_block_height + 1;

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
            checkpoint_file: devnet
                .checkpoint_file_handle
                .path()
                .to_string_lossy()
                .to_string(),
            database_location: DatabaseLocation::InMemory,
            rift_exchange_address: devnet.ethereum.rift_exchange_contract.address().to_string(),
            deploy_block_number: 0,
            btc_batch_rpc_size: 100,
            evm_log_chunk_size: 10000,
            proof_generator: ProofGeneratorType::Execute,
            enable_auto_light_client_update: false,
            auto_light_client_update_block_lag_threshold: 6,
            auto_light_client_update_check_interval_secs: 30,
        };
        hypernode.run().await.expect("Hypernode crashed");
    });

    println!(
        "Hypernode Bitcoin RPC URL: {:?}",
        devnet.bitcoin.rpc_url_with_cookie
    );
    let otc_swap = loop {
        let otc_swap = devnet
            .rift_indexer
            .get_otc_swap_by_order_index(new_order.index.to::<u64>())
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

    // now check again for ever until the swap is completed
    loop {
        let otc_swap = devnet
            .rift_indexer
            .get_otc_swap_by_order_index(new_order.index.to::<u64>())
            .await
            .unwrap();
        println!("OTCSwap Post Swap: {:#?}", otc_swap);
        if otc_swap.is_some_and(|otc_swap| otc_swap.swap_status() == SwapStatus::Completed) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    // ---3) Second Swap: Maker2 creates order, taker pays with Bitcoin again---

    println!("\n=== SECOND SWAP ===");

    // Approve tokens for second maker
    let approve_call2 = token_contract.approve(*rift_exchange.address(), deposit_amount);
    maker2_evm_provider
        .send_transaction(approve_call2.into_transaction_request())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    println!("Approved tokens for second maker");

    // Get new proof data for second order
    let (safe_leaf2, safe_siblings2, safe_peaks2) =
        devnet.rift_indexer.get_tip_proof().await.unwrap();
    let safe_leaf2: sol_bindings::BlockLeaf = safe_leaf2.into();

    let maker2_btc_wallet_script_pubkey = maker2.bitcoin_wallet.get_p2wpkh_script();
    let padded_script2 = maker2_btc_wallet_script_pubkey.to_bytes();

    // Create second order with different salt
    let deposit_params2 = CreateOrderParams {
        base: BaseCreateOrderParams {
            owner: maker2.ethereum_address,
            bitcoinScriptPubKey: padded_script2.into(),
            salt: [0x55; 32].into(), // Different salt for second order
            confirmationBlocks: 2,
            safeBlockLeaf: safe_leaf2,
        },
        expectedSats: expected_sats,
        depositAmount: deposit_amount,
        designatedReceiver: taker.ethereum_address,
        safeBlockSiblings: safe_siblings2.iter().map(From::from).collect(),
        safeBlockPeaks: safe_peaks2.iter().map(From::from).collect(),
    };

    let deposit_call2 = rift_exchange.createOrder(deposit_params2);
    let deposit_tx2 = maker2_evm_provider
        .send_transaction(deposit_call2.into_transaction_request())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let receipt_logs2 = deposit_tx2.inner.logs();
    let order_created_log2 = OrderCreated::decode_log(
        &receipt_logs2
            .iter()
            .find(|log| *log.topic0().unwrap() == OrderCreated::SIGNATURE_HASH)
            .unwrap()
            .inner,
    )
    .unwrap();

    let new_order2 = &order_created_log2.data.order;
    println!("Created second order: {:?}", new_order2);

    // Fund taker with more Bitcoin for second swap
    let funding_utxo2 = devnet
        .bitcoin
        .deal_bitcoin(
            taker.bitcoin_wallet.address.clone(),
            Amount::from_sat(funding_amount),
        )
        .await
        .unwrap();

    let transaction2: Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&funding_utxo2.hex).unwrap()).unwrap();

    let txvout2 = transaction2
        .output
        .iter()
        .enumerate()
        .find(|(_, output)| {
            output.script_pubkey.as_bytes() == wallet.get_p2wpkh_script().as_bytes()
                && output.value == Amount::from_sat(funding_amount)
        })
        .map(|(index, _)| index as u32)
        .unwrap();

    let serialized2 = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&transaction2);
    let mut reader2 = serialized2.as_slice();
    let canon_bitcoin_tx2 = Transaction::consensus_decode_from_finite_reader(&mut reader2).unwrap();
    let canon_txid2 = canon_bitcoin_tx2.compute_txid();

    // Build and broadcast second payment transaction
    let payment_tx2 = txn_builder::build_rift_payment_transaction_single_input(
        &vec![new_order2.clone()],
        &canon_txid2,
        &canon_bitcoin_tx2,
        txvout2,
        wallet,
        fee_sats,
    )
    .unwrap();

    let payment_tx_serialized2 = &mut Vec::new();
    payment_tx2
        .consensus_encode(payment_tx_serialized2)
        .unwrap();

    let _broadcast_tx2 = devnet
        .bitcoin
        .rpc_client
        .send_raw_transaction(payment_tx_serialized2.as_slice())
        .await
        .unwrap();
    println!("Second Bitcoin tx sent");

    // Mine blocks for second swap
    devnet.bitcoin.mine_blocks(2).await.unwrap();

    // Wait for second swap to enter challenge period
    let otc_swap2 = loop {
        let otc_swap = devnet
            .rift_indexer
            .get_otc_swap_by_order_index(new_order2.index.to::<u64>())
            .await
            .unwrap();
        println!("Second OTCSwap: {:#?}", otc_swap);
        if otc_swap
            .clone()
            .is_some_and(|otc_swap| otc_swap.swap_status() == SwapStatus::ChallengePeriod)
        {
            break otc_swap.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };

    // Warp ahead for second swap unlock
    let swap_unlock_timestamp2 = otc_swap2
        .payments
        .first()
        .unwrap()
        .payment
        .challengeExpiryTimestamp
        + 1;
    devnet
        .ethereum
        .funded_provider
        .anvil_set_time(swap_unlock_timestamp2)
        .await
        .unwrap();

    devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(1), None)
        .await
        .unwrap();

    // Wait for second swap to complete
    loop {
        let otc_swap = devnet
            .rift_indexer
            .get_otc_swap_by_order_index(new_order2.index.to::<u64>())
            .await
            .unwrap();
        println!("Second OTCSwap Post Swap: {:#?}", otc_swap);
        if otc_swap.is_some_and(|otc_swap| otc_swap.swap_status() == SwapStatus::Completed) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    println!("\n=== BOTH SWAPS COMPLETED SUCCESSFULLY ===");

    // stop the hypernode
    hypernode_handle.abort();
}
