use std::sync::Arc;

use super::*;
use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::Provider,
};
use devnet::{RiftDevnet, RiftExchangeWebsocket};
use eyre::OptionExt;
use hypernode::{
    txn_broadcast::{PreflightCheck, TransactionBroadcaster, TransactionExecutionResult},
    HypernodeArgs,
};
use rift_sdk::bindings::Types::BlockLeaf as ContractBlockLeaf;
use rift_sdk::bindings::Types::DepositLiquidityParams;
use rift_sdk::{
    bindings::RiftExchange::{self, ChainworkTooLow},
    create_websocket_wallet_provider, right_pad_to_25_bytes, DatabaseLocation,
};
use test_utils::create_funded_account;

async fn setup_deposit_txn() -> (
    devnet::RiftDevnet,
    Arc<RiftExchangeWebsocket>,
    DepositLiquidityParams,
    Address,
    TransactionBroadcaster,
) {
    let (maker_secret_bytes, maker_evm_wallet, maker_evm_address, maker_btc_wallet) =
        create_funded_account(1);
    let maker_evm_address_str = maker_evm_address.to_string();
    let (devnet, deploy_block_number) = RiftDevnet::setup(
        false,
        false,
        Some(maker_evm_address_str),
        None,
        None,
        DatabaseLocation::InMemory,
    )
    .await
    .unwrap();

    let maker_evm_provider = Arc::new(
        create_websocket_wallet_provider(
            devnet.ethereum.anvil.ws_endpoint_url().as_str(),
            maker_secret_bytes,
        )
        .await
        .unwrap(),
    );

    let hypernode_args = HypernodeArgs {
        evm_ws_rpc: devnet.ethereum.anvil.ws_endpoint_url().to_string(),
        btc_rpc: devnet.bitcoin.regtest.rpc_url(),
        private_key: hex::encode(maker_secret_bytes),
        checkpoint_file: devnet.checkpoint_file_path.clone(),
        database_location: DatabaseLocation::InMemory,
        rift_exchange_address: devnet.ethereum.rift_exchange_contract.address().to_string(),
        deploy_block_number,
        btc_batch_rpc_size: 100,
        mock_proof: false,
    };

    let transaction_broadcaster = hypernode::txn_broadcast::TransactionBroadcaster::new(
        maker_evm_provider.clone(),
        devnet.ethereum.anvil.endpoint().to_string(),
    );

    let rift_exchange = devnet.ethereum.rift_exchange_contract.clone();
    let token_contract = devnet.ethereum.token_contract.clone();

    // ---2) "Maker" address gets some ERC20 to deposit---

    println!("Maker address: {:?}", maker_evm_address);

    let deposit_amount = U256::from(1_000_000u128); //.01 wrapped bitcoin
    let expected_sats = 100_000_000u64; // The maker wants 1 bitcoin for their 1 million tokens (1 BTC = 1 cbBTC token)

    let decimals = devnet
        .ethereum
        .token_contract
        .decimals()
        .call()
        .await
        .unwrap()
        ._0;

    // Approve the RiftExchange to spend the maker's tokens
    let approve_call = token_contract.approve(*rift_exchange.address(), U256::MAX);
    maker_evm_provider
        .send_transaction(approve_call.into_transaction_request())
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

    let safe_leaf: sol_types::Types::BlockLeaf = safe_leaf.into();

    println!("Safe leaf tip (data engine): {:?}", safe_leaf);
    println!("Mmr root (data engine): {:?}", hex::encode(mmr_root));

    let light_client_height = devnet
        .ethereum
        .rift_exchange_contract
        .getLightClientHeight()
        .call()
        .await
        .unwrap()
        ._0;

    let mmr_root = devnet
        .ethereum
        .rift_exchange_contract
        .mmrRoot()
        .call()
        .await
        .unwrap()
        ._0;
    println!("Light client height (queried): {:?}", light_client_height);
    println!("Mmr root (queried): {:?}", mmr_root);

    let maker_btc_wallet_script_pubkey = maker_btc_wallet.get_p2wpkh_script();

    let padded_script = right_pad_to_25_bytes(maker_btc_wallet_script_pubkey.as_bytes());

    let deposit_params = DepositLiquidityParams {
        depositOwnerAddress: maker_evm_address,
        specifiedPayoutAddress: maker_evm_address,
        depositAmount: deposit_amount,
        expectedSats: expected_sats,
        btcPayoutScriptPubKey: padded_script.into(),
        depositSalt: [0x44; 32].into(), // this can be anything
        confirmationBlocks: 2,          // require 2 confirmations (1 block to mine + 1 additional)
        // TODO: This is hellacious, remove the 3 different types for BlockLeaf somehow
        safeBlockLeaf: ContractBlockLeaf {
            blockHash: safe_leaf.blockHash,
            height: safe_leaf.height,
            cumulativeChainwork: safe_leaf.cumulativeChainwork,
        },
        safeBlockSiblings: safe_siblings.iter().map(From::from).collect(),
        safeBlockPeaks: safe_peaks.iter().map(From::from).collect(),
    };
    println!("Deposit params: {:?}", deposit_params);
    (
        devnet,
        rift_exchange,
        deposit_params,
        maker_evm_address,
        transaction_broadcaster,
    )
}

#[tokio::test]
async fn test_txn_broadcast_success() {
    // devnet needs to be kept in scope so that the chains are kept alive
    let (_devnet, rift_exchange, deposit_params, maker_evm_address, transaction_broadcaster) =
        setup_deposit_txn().await;

    let deposit_call = rift_exchange.depositLiquidity(deposit_params);

    let deposit_calldata = deposit_call.calldata();

    let deposit_transaction_request = deposit_call
        .clone()
        .from(maker_evm_address)
        .into_transaction_request();

    let response = transaction_broadcaster
        .broadcast_transaction(
            deposit_calldata.clone(),
            deposit_transaction_request,
            PreflightCheck::Simulate,
        )
        .await
        .unwrap();

    assert!(response.is_success());
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
    let (_devnet, rift_exchange, mut deposit_params, maker_evm_address, transaction_broadcaster) =
        setup_deposit_txn().await;

    // Modify deposit params to have insufficient confirmation blocks
    deposit_params.confirmationBlocks = 1; // Too low - should cause ChainworkTooLow error

    let deposit_call = rift_exchange.depositLiquidity(deposit_params);
    let deposit_calldata = deposit_call.calldata();
    let deposit_transaction_request = deposit_call
        .clone()
        .from(maker_evm_address)
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
    let (_devnet, rift_exchange, mut deposit_params, maker_evm_address, transaction_broadcaster) =
        setup_deposit_txn().await;

    // Modify deposit params to have insufficient confirmation blocks
    deposit_params.confirmationBlocks = 1; // Too low - should cause ChainworkTooLow error

    let deposit_call = rift_exchange.depositLiquidity(deposit_params);
    let deposit_calldata = deposit_call.calldata();
    let deposit_transaction_request = deposit_call
        .clone()
        .from(maker_evm_address)
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
    deposit_transaction_request.nonce = Some(nonce + 1);

    // Create a second identical transaction request
    // This should cause a nonce error since we're trying to use the same nonce
    let second_deposit_call = rift_exchange.depositLiquidity(deposit_params);
    let second_deposit_calldata = second_deposit_call.calldata();
    let mut second_deposit_transaction_request = second_deposit_call
        .clone()
        .from(maker_evm_address)
        .into_transaction_request();
    second_deposit_transaction_request.nonce = Some(nonce + 1);

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
