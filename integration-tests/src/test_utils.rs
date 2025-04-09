use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address},
    signers::local::LocalSigner,
};
use once_cell::sync::OnceCell;
use rift_sdk::txn_builder::P2WPKHBitcoinWallet;

use futures::channel::oneshot;
use std::{
    collections::HashMap,
    fmt::Write,
    sync::{Arc, Mutex},
};
use tracing::{Event, Subscriber};
use tracing_subscriber::{
    fmt,
    layer::{Context, Layer, SubscriberExt},
    util::SubscriberInitExt,
    EnvFilter,
};

use bitcoincore_rpc_async::RpcApi;

use alloy::{eips::BlockNumberOrTag, primitives::U256, providers::Provider};
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

/// Holds the components of a multichain account including secret bytes and wallets.
#[derive(Debug)]
pub struct MultichainAccount {
    /// The raw secret bytes used to derive wallets
    pub secret_bytes: [u8; 32],
    /// The Ethereum wallet derived from the secret
    pub ethereum_wallet: EthereumWallet,
    /// The Ethereum address associated with the wallet
    pub ethereum_address: Address,
    /// The Bitcoin wallet derived from the secret
    pub bitcoin_wallet: P2WPKHBitcoinWallet,
}

impl MultichainAccount {
    /// Creates a new multichain account from the given derivation salt
    pub fn new(derivation_salt: u32) -> Self {
        let secret_bytes: [u8; 32] = keccak256(derivation_salt.to_le_bytes()).into();

        let ethereum_wallet =
            EthereumWallet::new(LocalSigner::from_bytes(&secret_bytes.into()).unwrap());

        let ethereum_address = ethereum_wallet.default_signer().address();

        let bitcoin_wallet =
            P2WPKHBitcoinWallet::from_secret_bytes(&secret_bytes, ::bitcoin::Network::Regtest);

        Self {
            secret_bytes,
            ethereum_wallet,
            ethereum_address,
            bitcoin_wallet,
        }
    }

    /// Creates a new multichain account with the Bitcoin network explicitly specified
    pub fn with_network(derivation_salt: u32, network: ::bitcoin::Network) -> Self {
        let secret_bytes: [u8; 32] = keccak256(derivation_salt.to_le_bytes()).into();

        let ethereum_wallet =
            EthereumWallet::new(LocalSigner::from_bytes(&secret_bytes.into()).unwrap());

        let ethereum_address = ethereum_wallet.default_signer().address();

        let bitcoin_wallet = P2WPKHBitcoinWallet::from_secret_bytes(&secret_bytes, network);

        Self {
            secret_bytes,
            ethereum_wallet,
            ethereum_address,
            bitcoin_wallet,
        }
    }
}

pub async fn create_deposit(
    using_bitcoin: bool,
) -> (
    devnet::RiftDevnet,
    Arc<RiftExchangeWebsocket>,
    DepositLiquidityParams,
    MultichainAccount,
    TransactionBroadcaster,
) {
    let maker = MultichainAccount::new(1);
    let (mut devnet, deploy_block_number) = RiftDevnet::builder()
        .using_bitcoin(using_bitcoin)
        .funded_evm_address(maker.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
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

    let transaction_broadcaster = hypernode::txn_broadcast::TransactionBroadcaster::new(
        maker_evm_provider.clone(),
        devnet.ethereum.anvil.endpoint().to_string(),
        &mut devnet.join_set,
    );

    let rift_exchange = devnet.ethereum.rift_exchange_contract.clone();
    let token_contract = devnet.ethereum.token_contract.clone();

    // ---2) "Maker" address gets some ERC20 to deposit---

    println!("Maker address: {:?}", maker.ethereum_address);

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
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    println!("Approved");

    // ---3) Maker deposits liquidity into RiftExchange---
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
        specifiedPayoutAddress: maker.ethereum_address,
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
        maker,
        transaction_broadcaster,
    )
}

pub async fn send_bitcoin_for_deposit(
    devnet: &RiftDevnet,
    taker: &MultichainAccount,
    vault: &DepositVault,
) {
    let dealed_amount = vault.expectedSats * 2; // deal double so we have plenty to cover the fee

    // now send some bitcoin to the taker's btc address so we can get a UTXO to spend
    let funding_utxo = devnet
        .bitcoin
        .deal_bitcoin(
            taker.bitcoin_wallet.address.clone(),
            Amount::from_sat(dealed_amount),
        ) // 1.5 bitcoin
        .await
        .unwrap();

    let wallet = &taker.bitcoin_wallet;
    let fee_sats = 1000;
    let transaction = funding_utxo.transaction().unwrap();

    // if the predicate is true, we can spend it
    let txvout = transaction
        .output
        .iter()
        .enumerate()
        .find(|(_, output)| {
            output.script_pubkey.as_bytes() == wallet.get_p2wpkh_script().as_bytes()
                && output.value == Amount::from_sat(dealed_amount)
        })
        .map(|(index, _)| index as u32)
        .unwrap();

    let serialized = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&transaction);
    let canon_bitcoin_tx: Transaction = bitcoin::consensus::deserialize(&serialized).unwrap();
    let canon_txid = canon_bitcoin_tx.compute_txid();

    // ---4) Taker broadcasts a Bitcoin transaction paying that scriptPubKey---
    let payment_tx = txn_builder::build_rift_payment_transaction(
        vault,
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
    devnet
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
}

static LOGGING: OnceCell<()> = OnceCell::new();

pub fn setup_test_tracing() {
    LOGGING.get_or_init(|| {
        // Only init tracing if --nocapture is passed
        let has_nocapture = std::env::args().any(|arg| arg == "--nocapture");
        if has_nocapture {
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
                )
                .init();
        }
    });
}
