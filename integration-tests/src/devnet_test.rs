use ::bitcoin::consensus::{Decodable, Encodable};
use ::bitcoin::hashes::Hash;
use ::bitcoin::{Amount, Transaction};
use accumulators::mmr::{leaf_count_to_mmr_size, map_leaf_index_to_element_index};
use alloy::hex;
use alloy::network::EthereumWallet;
use alloy::primitives::utils::format_units;
use alloy::primitives::U256;
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, WalletProvider, WsConnect};
use alloy::signers::local::LocalSigner;
use alloy::sol_types::SolEvent;
use bitcoin_light_client_core::light_client::Header;
use bitcoin_light_client_core::{ChainTransition, ProvenLeaf, VerifiedBlock};
use bitcoincore_rpc_async::bitcoin::hashes::Hash as BitcoinHash;
use bitcoincore_rpc_async::RpcApi;
use devnet::RiftDevnet;
use rift_core::giga::RiftProgramInput;
use rift_core::spv::generate_bitcoin_txn_merkle_proof;
use rift_core::OrderFillingTransaction;
use rift_sdk::bitcoin_utils::BitcoinClientExt;
use rift_sdk::create_websocket_wallet_provider;
use rift_sdk::proof_generator::{ProofGeneratorType, RiftProofGenerator};
use rift_sdk::txn_builder::{self, serialize_no_segwit, P2WPKHBitcoinWallet};
use rift_sdk::{get_retarget_height_from_block_height, DatabaseLocation};
use sol_bindings::{
    BaseCreateOrderParams, BlockProofParams, CreateOrderParams, OrderCreated, PaymentsCreated,
    SettleOrderParams, SubmitPaymentProofParams,
};
use tokio::signal;

#[tokio::test]
async fn test_devnet_boots() {
    RiftDevnet::builder()
        .using_esplora(true)
        .build()
        .await
        .unwrap();
}
