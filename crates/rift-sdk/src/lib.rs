pub mod bitcoin_utils;
pub mod checkpoint_mmr;
mod errors;
pub mod indexed_mmr;
pub mod proof_generator;
pub mod txn_builder;

use alloy::network::{Ethereum, EthereumWallet};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use alloy::providers::{Identity, ProviderBuilder, RootProvider, WsConnect};
use alloy::pubsub::{ConnectionHandle, PubSubConnect};
use alloy::rpc::client::ClientBuilder;
use alloy::signers::local::LocalSigner;
use alloy::signers::Signer;
use alloy::transports::{impl_future, TransportResult};
use alloy::{providers::Provider, pubsub::PubSubFrontend};
use backoff::exponential::ExponentialBackoff;
use bitcoin::hashes::hex::FromHex;
use rift_core::giga::RiftProgramInput;
use sol_bindings::RiftExchange::RiftExchangeInstance;
use sp1_sdk::{include_elf, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use sp1_sdk::{EnvProver, HashableKey};
use sp1_sdk::{Prover, SP1ProvingKey};
use std::fmt::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

pub type WebsocketWalletProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<PubSubFrontend>,
    PubSubFrontend,
    Ethereum,
>;

pub type RiftExchangeClient = RiftExchangeInstance<
    PubSubFrontend,
    Arc<
        FillProvider<
            JoinFill<
                JoinFill<
                    Identity,
                    JoinFill<
                        GasFiller,
                        JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>,
                    >,
                >,
                WalletFiller<EthereumWallet>,
            >,
            RootProvider<PubSubFrontend>,
            PubSubFrontend,
            Ethereum,
        >,
    >,
>;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const RIFT_PROGRAM_ELF: &[u8] = include_elf!("rift-program");

/// This is expensive to compute, so if you have a proof generator, use that instead.
pub fn get_rift_program_hash() -> [u8; 32] {
    let client = ProverClient::builder().mock().build();
    let (_, vk) = client.setup(RIFT_PROGRAM_ELF);
    vk.bytes32_raw()
}

pub fn load_hex_bytes(file: &str) -> Vec<u8> {
    let hex_string = std::fs::read_to_string(file).expect("Failed to read file");
    Vec::<u8>::from_hex(&hex_string).expect("Failed to parse hex")
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn get_retarget_height_from_block_height(block_height: u32) -> u32 {
    block_height - (block_height % 2016)
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Where to store the database (in-memory or on disk).
pub enum DatabaseLocation {
    InMemory,
    Directory(String),
}

impl FromStr for DatabaseLocation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "memory" => Ok(DatabaseLocation::InMemory),
            s => Ok(DatabaseLocation::Directory(s.to_string())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RetryWsConnect(WsConnect);

impl PubSubConnect for RetryWsConnect {
    fn is_local(&self) -> bool {
        self.0.is_local()
    }

    fn connect(&self) -> impl_future!(<Output = TransportResult<ConnectionHandle>>) {
        self.0.connect()
    }

    async fn try_reconnect(&self) -> TransportResult<ConnectionHandle> {
        backoff::future::retry(
            ExponentialBackoff::<backoff::SystemClock>::default(),
            || async { Ok(self.0.try_reconnect().await?) },
        )
        .await
    }
}

pub async fn create_websocket_provider(
    evm_rpc_websocket_url: &str,
) -> errors::Result<impl Provider<PubSubFrontend>> {
    let ws = RetryWsConnect(WsConnect::new(evm_rpc_websocket_url));
    let client = ClientBuilder::default()
        .pubsub(ws)
        .await
        .map_err(|e| errors::RiftSdkError::WebsocketProviderError(e.to_string()))?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_client(client);

    Ok(provider)
}

pub fn right_pad_to_25_bytes(input: &[u8]) -> [u8; 25] {
    let mut padded = [0u8; 25];
    let copy_len = input.len().min(25);
    padded[..copy_len].copy_from_slice(&input[..copy_len]);
    padded
}

pub async fn create_websocket_wallet_provider(
    evm_rpc_websocket_url: &str,
    private_key: [u8; 32],
) -> errors::Result<WebsocketWalletProvider> {
    let ws = RetryWsConnect(WsConnect::new(evm_rpc_websocket_url));
    let client = ClientBuilder::default()
        .pubsub(ws)
        .await
        .map_err(|e| errors::RiftSdkError::WebsocketProviderError(e.to_string()))?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(EthereumWallet::new(
            LocalSigner::from_str(&hex::encode(private_key))
                .map_err(|e| errors::RiftSdkError::InvalidPrivateKey(e.to_string()))?,
        ))
        .on_client(client);

    Ok(provider)
}
