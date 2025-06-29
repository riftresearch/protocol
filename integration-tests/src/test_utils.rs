use rift_sdk::MultichainAccount;

use std::sync::Arc;

use alloy::{primitives::U256, providers::Provider};
use devnet::{RiftDevnet, RiftExchangeHarnessWebsocket};

use rift_sdk::txn_broadcast::TransactionBroadcaster;

use rift_sdk::create_websocket_wallet_provider;
use sol_bindings::{BaseCreateOrderParams, BlockLeaf as ContractBlockLeaf, CreateOrderParams};

pub async fn create_deposit(
    _using_bitcoin: bool,
) -> (
    devnet::RiftDevnet,
    Arc<RiftExchangeHarnessWebsocket>,
    CreateOrderParams,
    MultichainAccount,
    TransactionBroadcaster,
) {
    let maker = MultichainAccount::new(1);
    let (mut devnet, _deploy_block_number) = RiftDevnet::builder()
        .funded_evm_address(maker.ethereum_address.to_string())
        .build()
        .await
        .unwrap();

    let maker_evm_provider = Arc::new(
        create_websocket_wallet_provider(
            devnet.ethereum.anvil.ws_endpoint_url().as_str(),
            maker.secret_bytes,
        )
        .await
        .unwrap(),
    );

    let transaction_broadcaster = TransactionBroadcaster::new(
        maker_evm_provider.clone(),
        devnet.ethereum.anvil.endpoint(),
        &mut devnet.join_set,
    );

    let rift_exchange = devnet.ethereum.rift_exchange_contract.clone();
    let token_contract = devnet.ethereum.token_contract.clone();

    // ---2) "Maker" address gets some ERC20 to deposit---

    println!("Maker address: {:?}", maker.ethereum_address);

    let deposit_amount = U256::from(1_000_000u128); //.01 wrapped bitcoin
    let expected_sats = 100_000_000u64; // The maker wants 1 bitcoin for their 1 million tokens (1 BTC = 1 cbBTC token)

    let _decimals = devnet
        .ethereum
        .token_contract
        .decimals()
        .call()
        .await
        .unwrap();

    // Approve the RiftExchange to spend the maker's tokens
    let approve_call = token_contract.approve(*rift_exchange.address(), U256::MAX);
    maker_evm_provider
        .send_transaction(approve_call.into_transaction_request())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    println!("Approved");

    // ---3) Maker deposits liquidity into RiftExchange---
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
            safeBlockLeaf: ContractBlockLeaf {
                blockHash: safe_leaf.blockHash,
                height: safe_leaf.height,
                cumulativeChainwork: safe_leaf.cumulativeChainwork,
            },
        },
        designatedReceiver: maker.ethereum_address,
        depositAmount: deposit_amount,
        expectedSats: expected_sats,
        safeBlockSiblings: safe_siblings.iter().map(From::from).collect(),
        safeBlockPeaks: safe_peaks.iter().map(From::from).collect(),
    };
    println!("Deposit params: {:?}", deposit_params);
    (
        devnet,
        rift_exchange,
        deposit_params,
        maker,
        transaction_broadcaster,
    )
}
