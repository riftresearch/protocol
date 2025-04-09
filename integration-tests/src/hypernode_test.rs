use alloy::{
    network::EthereumWallet,
    primitives::{utils::format_units, U256},
    providers::{ext::AnvilApi, ProviderBuilder, WsConnect},
    signers::local::LocalSigner,
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
use rift_core::vaults::hash_deposit_vault;
use rift_sdk::{
    proof_generator::{ProofGeneratorType, RiftProofGenerator},
    right_pad_to_25_bytes,
    txn_builder::{self, serialize_no_segwit, P2WPKHBitcoinWallet},
    DatabaseLocation,
};
use sol_bindings::{RiftExchange, Types::DepositLiquidityParams};
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
        .with_recommended_fillers()
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
        .unwrap()
        ._0;

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

    let safe_leaf: sol_bindings::Types::BlockLeaf = safe_leaf.into();

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

    let maker_btc_wallet_script_pubkey = maker.bitcoin_wallet.get_p2wpkh_script();

    let padded_script = right_pad_to_25_bytes(maker_btc_wallet_script_pubkey.as_bytes());

    let deposit_params = DepositLiquidityParams {
        depositOwnerAddress: maker.ethereum_address,
        specifiedPayoutAddress: taker.ethereum_address,
        depositAmount: deposit_amount,
        expectedSats: expected_sats,
        btcPayoutScriptPubKey: padded_script.into(),
        depositSalt: [0x44; 32].into(), // this can be anything
        confirmationBlocks: 2,          // require 2 confirmations (1 block to mine + 1 additional)
        // TODO: This is hellacious, remove the 3 different types for BlockLeaf somehow
        safeBlockLeaf: safe_leaf,
        safeBlockSiblings: safe_siblings.iter().map(From::from).collect(),
        safeBlockPeaks: safe_peaks.iter().map(From::from).collect(),
    };
    println!("Deposit params: {:?}", deposit_params);

    let deposit_call = rift_exchange.depositLiquidity(deposit_params);

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
    let vaults_updated_log = RiftExchange::VaultsUpdated::decode_log(
        &receipt_logs
            .iter()
            .find(|log| *log.topic0().unwrap() == RiftExchange::VaultsUpdated::SIGNATURE_HASH)
            .unwrap()
            .inner,
        false,
    )
    .unwrap();

    let new_vault = &vaults_updated_log.data.vaults[0];
    let vault_commitment = hash_deposit_vault(&new_vault);

    println!("Vault commitment: {:?}", hex::encode(vault_commitment));

    println!("Created vault: {:?}", new_vault);

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
        &new_vault,
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
        let hypernode_args = HypernodeArgs {
            evm_ws_rpc: devnet.ethereum.anvil.ws_endpoint_url().to_string(),
            btc_rpc: rpc_url_with_cookie.clone(),
            private_key: hex::encode(hypernode_account.secret_bytes),
            checkpoint_file: devnet.checkpoint_file_path.clone(),
            database_location: DatabaseLocation::InMemory,
            rift_exchange_address: devnet.ethereum.rift_exchange_contract.address().to_string(),
            deploy_block_number: 0,
            btc_batch_rpc_size: 100,
            proof_generator: ProofGeneratorType::Execute,
        };
        hypernode::run(hypernode_args)
            .await
            .expect("Hypernode crashed");
    });

    println!(
        "Hypernode Bitcoin RPC URL: {:?}",
        devnet.bitcoin.rpc_url_with_cookie
    );
    let otc_swap = loop {
        let otc_swap = devnet
            .contract_data_engine
            .get_otc_swap_by_deposit_id(vault_commitment)
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
    let swap_unlock_timestamp = otc_swap.swap_proofs[0].swap.liquidityUnlockTimestamp;
    devnet
        .ethereum
        .funded_provider
        .anvil_set_time(swap_unlock_timestamp)
        .await
        .unwrap();

    devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(U256::from(1)), None)
        .await
        .unwrap();
    // now check again for ever until the swap is completed
    loop {
        let otc_swap = devnet
            .contract_data_engine
            .get_otc_swap_by_deposit_id(vault_commitment)
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
