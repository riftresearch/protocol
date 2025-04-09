use std::sync::Arc;

use crate::test_utils::{create_deposit, MultichainAccount};
use bitcoincore_rpc_async::RpcApi;

use super::*;
use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::Provider,
};
use bitcoin::{consensus::Encodable, hashes::Hash, Amount, Transaction};
use devnet::{RiftDevnet, RiftExchangeWebsocket};
use eyre::OptionExt;
use hypernode::{
    txn_broadcast::{PreflightCheck, TransactionBroadcaster, TransactionExecutionResult},
    HypernodeArgs,
};
use rift_sdk::{
    create_websocket_wallet_provider, proof_generator::ProofGeneratorType, right_pad_to_25_bytes,
    txn_builder, DatabaseLocation,
};
use sol_bindings::{
    RiftExchange,
    Types::{BlockLeaf as ContractBlockLeaf, DepositLiquidityParams, DepositVault},
};

#[tokio::test]
async fn test_txn_broadcast_success() {
    // devnet needs to be kept in scope so that the chains are kept alive
    let (_devnet, rift_exchange, deposit_params, maker, transaction_broadcaster) =
        create_deposit(false).await;

    let deposit_call = rift_exchange.depositLiquidity(deposit_params);

    let deposit_calldata = deposit_call.calldata();

    let deposit_transaction_request = deposit_call
        .clone()
        .from(maker.ethereum_address)
        .into_transaction_request();

    let response = transaction_broadcaster
        .broadcast_transaction(
            deposit_calldata.clone(),
            deposit_transaction_request,
            PreflightCheck::Simulate,
        )
        .await
        .unwrap();

    assert!(response.is_success(), "Transaction failed: {:?}", response);
    /*
    match response {
        TransactionExecutionResult::Success(receipt) => {
            println!("Transaction successful: {:?}", receipt);
        }
        TransactionExecutionResult::Revert(error) => {
            let decoded_error = error
                .error_payload
                .as_decoded_error::<RiftExchange::RiftExchangeErrors>(false)
                .ok_or_eyre("Could not decode error")
                .unwrap();
            println!("Transaction reverted: {:?}", decoded_error);
        }
        TransactionExecutionResult::UnknownError(error) => {
            println!("Transaction unknown error: {:?}", error);
        }
        TransactionExecutionResult::InvalidRequest(error) => {
            println!("Transaction invalid request: {:?}", error);
        }

    }
    */
}

#[tokio::test]
async fn test_txn_broadcast_handles_revert_in_sim() {
    // Setup is identical to test_txn_broadcast_success
    let (_devnet, rift_exchange, mut deposit_params, maker, transaction_broadcaster) =
        create_deposit(false).await;

    // Modify deposit params to have insufficient confirmation blocks
    deposit_params.confirmationBlocks = 1; // Too low - should cause ChainworkTooLow error

    let deposit_call = rift_exchange.depositLiquidity(deposit_params);
    let deposit_calldata = deposit_call.calldata();
    let deposit_transaction_request = deposit_call
        .clone()
        .from(maker.ethereum_address)
        .into_transaction_request();

    let response = transaction_broadcaster
        .broadcast_transaction(
            deposit_calldata.clone(),
            deposit_transaction_request,
            PreflightCheck::Simulate,
        )
        .await
        .unwrap();

    // Assert that the transaction reverted with NotEnoughConfirmationBlocks error
    match response {
        TransactionExecutionResult::Revert(error) => {
            let decoded_error = error
                .error_payload
                .as_decoded_error::<RiftExchange::RiftExchangeErrors>(false)
                .unwrap();
            println!("Decoded error: {:?}", decoded_error);
            assert!(matches!(
                decoded_error,
                RiftExchange::RiftExchangeErrors::NotEnoughConfirmationBlocks(_)
            ));
        }
        _ => panic!("Expected transaction to revert with NotEnoughConfirmationBlocks error"),
    }
}
#[tokio::test]
async fn test_txn_broadcast_handles_revert_in_send() {
    // Setup is identical to test_txn_broadcast_success
    let (_devnet, rift_exchange, mut deposit_params, maker, transaction_broadcaster) =
        create_deposit(false).await;

    // Modify deposit params to have insufficient confirmation blocks
    deposit_params.confirmationBlocks = 1; // Too low - should cause ChainworkTooLow error

    let deposit_call = rift_exchange.depositLiquidity(deposit_params);
    let deposit_calldata = deposit_call.calldata();
    let deposit_transaction_request = deposit_call
        .clone()
        .from(maker.ethereum_address)
        .into_transaction_request();

    let response = transaction_broadcaster
        .broadcast_transaction(
            deposit_calldata.clone(),
            deposit_transaction_request,
            PreflightCheck::None,
        )
        .await
        .unwrap();

    // Assert that the transaction reverted with NotEnoughConfirmationBlocks error
    match response {
        TransactionExecutionResult::Revert(error) => {
            let decoded_error = error
                .error_payload
                .as_decoded_error::<RiftExchange::RiftExchangeErrors>(false)
                .unwrap();
            println!("Decoded error: {:?}", decoded_error);
            assert!(matches!(
                decoded_error,
                RiftExchange::RiftExchangeErrors::NotEnoughConfirmationBlocks(_)
            ));
        }
        _ => panic!("Expected transaction to revert with NotEnoughConfirmationBlocks error"),
    }
}

/*
// TODO: Ensure txn broadcast is handling nonce errors
#[tokio::test]
async fn test_txn_broadcast_handles_nonce_error() {
    // Setup is identical to test_txn_broadcast_success
    let (devnet, rift_exchange, deposit_params, maker_evm_address, transaction_broadcaster) =
        setup_deposit_txn().await;

    let deposit_call = rift_exchange.depositLiquidity(deposit_params.clone());
    let deposit_calldata = deposit_call.calldata();

    let nonce = devnet
        .ethereum
        .funded_provider
        .get_transaction_count(maker_evm_address)
        .await
        .unwrap();

    let mut deposit_transaction_request = deposit_call
        .clone()
        .from(maker_evm_address)
        .into_transaction_request();
    deposit_transaction_request.nonce = Some(nonce);

    // Create a second identical transaction request
    // This should cause a nonce error since we're trying to use the same nonce
    let second_deposit_call = rift_exchange.depositLiquidity(deposit_params);
    let second_deposit_calldata = second_deposit_call.calldata();
    let mut second_deposit_transaction_request = second_deposit_call
        .clone()
        .from(maker_evm_address)
        .into_transaction_request();
    second_deposit_transaction_request.nonce = Some(nonce + 1);

    println!("Sending first transaction");
    // Send first transaction
    let first_response = transaction_broadcaster
        .broadcast_transaction(
            deposit_calldata.clone(),
            deposit_transaction_request,
            PreflightCheck::None,
        )
        .await
        .unwrap();
    println!("First response: {:?}", first_response);

    // Immediately try to send second transaction with same nonce
    let second_response = transaction_broadcaster
        .broadcast_transaction(
            second_deposit_calldata.clone(),
            second_deposit_transaction_request,
            PreflightCheck::None,
        )
        .await
        .unwrap();
    println!("Second response: {:?}", second_response);
    // First transaction should succeed
    assert!(first_response.is_success());

    // Second transaction should fail with a nonce error
    match second_response {
        TransactionExecutionResult::InvalidRequest(error) => {
            assert!(error.contains("nonce"), "Error should mention nonce issue");
        }
        _ => {
            tokio::signal::ctrl_c().await.unwrap();
            panic!("Expected transaction to fail with nonce error");
        }
    }
}
*/
