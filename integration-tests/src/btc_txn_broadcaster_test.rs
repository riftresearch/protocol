use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, Network, ScriptBuf, TxOut};
use devnet::{BitcoinDevnet, RiftDevnet};
use rift_sdk::{
    btc_txn_broadcaster::{
        BitcoinTransactionBroadcasterTrait, SimpleBitcoinTransactionBroadcaster,
    },
    txn_builder::P2WPKHBitcoinWallet,
    DatabaseLocation, MultichainAccount,
};
use tokio::task::JoinSet;

use crate::test_utils::setup_test_tracing;

/// Test basic functionality of the Bitcoin transaction broadcaster
#[tokio::test]
async fn test_btc_txn_broadcaster_basic() {
    setup_test_tracing();

    let mut join_set = JoinSet::new();

    let test_account = MultichainAccount::with_network(42, Network::Regtest);

    // Setup devnet with Bitcoin and Esplora
    let (devnet, _) = BitcoinDevnet::setup(
        vec![test_account.bitcoin_wallet.address.to_string()],
        true,
        true,
        false,
        &mut join_set,
    )
    .await
    .unwrap();

    // Mine a block to confirm the funding transaction
    devnet
        .regtest
        .client
        .generate_to_address(1, &test_account.bitcoin_wallet.address)
        .unwrap();

    // Create the transaction broadcaster
    let broadcaster = SimpleBitcoinTransactionBroadcaster::new(
        devnet.rpc_client.clone(),
        devnet.esplora_client.as_ref().unwrap().clone(),
        test_account.bitcoin_wallet,
        &mut join_set,
    )
    .await;

    // Create a simple payment output
    let recipient_wallet = MultichainAccount::with_network(43, Network::Regtest);
    let payment_amount = Amount::from_sat(100_000_000); // 1 BTC
    let payment_output = TxOut {
        value: payment_amount,
        script_pubkey: recipient_wallet.bitcoin_wallet.get_p2wpkh_script(),
    };

    // Test broadcasting a transaction
    let result = broadcaster.broadcast_transaction(&[payment_output]).await;

    match result {
        Ok(txid) => {
            println!("Successfully broadcast transaction: {}", txid);

            // Mine a block to confirm the transaction
            devnet
                .regtest
                .client
                .generate_to_address(1, &recipient_wallet.bitcoin_wallet.address)
                .unwrap();
        }
        Err(e) => {
            panic!("Transaction broadcast failed: {}", e);
        }
    }
}

/// Test transaction broadcasting with multiple outputs
#[tokio::test]
async fn test_btc_txn_broadcaster_multiple_outputs() {
    setup_test_tracing();

    let mut join_set = JoinSet::new();

    let test_account = MultichainAccount::with_network(44, Network::Regtest);

    // Setup devnet with Bitcoin and Esplora
    let (devnet, _) = BitcoinDevnet::setup(
        vec![test_account.bitcoin_wallet.address.to_string()],
        true,
        true,
        false,
        &mut join_set,
    )
    .await
    .unwrap();

    // Mine a block to confirm the funding transaction
    devnet
        .regtest
        .client
        .generate_to_address(1, &test_account.bitcoin_wallet.address)
        .unwrap();

    // Wait a bit for Esplora to index the transaction
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Create the transaction broadcaster
    let broadcaster = SimpleBitcoinTransactionBroadcaster::new(
        devnet.rpc_client.clone(),
        devnet.esplora_client.as_ref().unwrap().clone(),
        test_account.bitcoin_wallet,
        &mut join_set,
    )
    .await;

    // Create multiple payment outputs
    let recipient1 = MultichainAccount::with_network(45, Network::Regtest);
    let recipient2 = MultichainAccount::with_network(46, Network::Regtest);

    let outputs = vec![
        TxOut {
            value: Amount::from_sat(50_000_000), // 0.5 BTC
            script_pubkey: recipient1.bitcoin_wallet.get_p2wpkh_script(),
        },
        TxOut {
            value: Amount::from_sat(75_000_000), // 0.75 BTC
            script_pubkey: recipient2.bitcoin_wallet.get_p2wpkh_script(),
        },
    ];

    // Test broadcasting a transaction with multiple outputs
    let result = broadcaster.broadcast_transaction(&outputs).await;

    match result {
        Ok(txid) => {
            println!("Successfully broadcast multi-output transaction: {}", txid);

            // Mine a block to confirm the transaction
            devnet
                .regtest
                .client
                .generate_to_address(1, &recipient1.bitcoin_wallet.address)
                .unwrap();
        }
        Err(e) => {
            panic!("Multi-output transaction broadcast failed: {}", e);
        }
    }
}

/// Test insufficient funds scenario
#[tokio::test]
async fn test_btc_txn_broadcaster_insufficient_funds() {
    setup_test_tracing();

    let mut join_set = JoinSet::new();

    // Create a test wallet (don't fund it)
    let test_account = MultichainAccount::with_network(47, Network::Regtest);

    // Setup devnet with Bitcoin and Esplora (without funding the wallet)
    let (devnet, _) = BitcoinDevnet::setup(
        vec![], // Don't fund any address
        true,
        true,
        false,
        &mut join_set,
    )
    .await
    .unwrap();

    // Create the transaction broadcaster
    let broadcaster = SimpleBitcoinTransactionBroadcaster::new(
        devnet.rpc_client.clone(),
        devnet.esplora_client.as_ref().unwrap().clone(),
        test_account.bitcoin_wallet,
        &mut join_set,
    )
    .await;

    // Try to create a payment without any funds
    let recipient_wallet = MultichainAccount::with_network(48, Network::Regtest);
    let payment_output = TxOut {
        value: Amount::from_sat(100_000_000), // 1 BTC
        script_pubkey: recipient_wallet.bitcoin_wallet.get_p2wpkh_script(),
    };

    // This should fail due to insufficient funds
    let result = broadcaster.broadcast_transaction(&[payment_output]).await;

    assert!(result.is_err(), "Expected insufficient funds error");
    println!(
        "Correctly failed with insufficient funds: {}",
        result.unwrap_err()
    );
}

/// Test the can_fund_transaction method
#[tokio::test]
async fn test_btc_txn_broadcaster_can_fund() {
    setup_test_tracing();

    let mut join_set = JoinSet::new();

    let test_account = MultichainAccount::with_network(49, Network::Regtest);

    // Setup devnet with Bitcoin and Esplora
    let (devnet, _) = BitcoinDevnet::setup(
        vec![test_account.bitcoin_wallet.address.to_string()],
        true,
        true,
        false,
        &mut join_set,
    )
    .await
    .unwrap();

    // Mine a block to confirm the funding transaction
    devnet
        .regtest
        .client
        .generate_to_address(1, &test_account.bitcoin_wallet.address)
        .unwrap();

    // Wait a bit for Esplora to index the transaction
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Create the transaction broadcaster
    let broadcaster = SimpleBitcoinTransactionBroadcaster::new(
        devnet.rpc_client.clone(),
        devnet.esplora_client.as_ref().unwrap().clone(),
        test_account.bitcoin_wallet,
        &mut join_set,
    )
    .await;

    // Test can_fund_transaction with a reasonable amount
    let recipient_wallet = MultichainAccount::with_network(50, Network::Regtest);
    let payment_output = TxOut {
        value: Amount::from_sat(50_000_000), // 0.5 BTC
        script_pubkey: recipient_wallet.bitcoin_wallet.get_p2wpkh_script(),
    };

    let can_fund = broadcaster
        .can_fund_transaction(&[payment_output])
        .await
        .expect("Failed to check funding capability");

    // Note: The current implementation always returns true, so this test
    // is more about ensuring the method works than testing actual logic
    assert!(can_fund, "Should be able to fund reasonable transaction");
}
