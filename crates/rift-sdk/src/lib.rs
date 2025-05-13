pub mod bitcoin_utils;
pub mod btc_txn_broadcaster;
pub mod checkpoint_mmr;
mod errors;
pub mod indexed_mmr;
pub mod proof_generator;
pub mod txn_broadcast;
pub mod txn_builder;

use alloy::network::EthereumWallet;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use alloy::providers::Provider;
use alloy::providers::{DynProvider, Identity, ProviderBuilder, RootProvider, WsConnect};
use alloy::pubsub::{ConnectionHandle, PubSubConnect};
use alloy::rpc::client::ClientBuilder;
use alloy::signers::local::LocalSigner;
use alloy::transports::{impl_future, TransportResult};
use backoff::exponential::ExponentialBackoff;
use bitcoin::hashes::hex::FromHex;
use sol_bindings::RiftExchangeHarnessInstance;
use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient};
use std::fmt::Write;
use std::str::FromStr;

pub type WebsocketWalletProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

pub type RiftExchangeHarnessClient = RiftExchangeHarnessInstance<DynProvider>;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const RIFT_PROGRAM_ELF: &[u8] = include_elf!("rift-program");

/// This is expensive to compute, so if you have a `ProofGenerator` instantiated, use that instead.
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

/// Creates a type erased websocket provider
pub async fn create_websocket_provider(evm_rpc_websocket_url: &str) -> errors::Result<DynProvider> {
    let ws = RetryWsConnect(WsConnect::new(evm_rpc_websocket_url));
    let client = ClientBuilder::default()
        .pubsub(ws)
        .await
        .map_err(|e| errors::RiftSdkError::WebsocketProviderError(e.to_string()))?;

    Ok(ProviderBuilder::new().on_client(client).erased())
}

/// Creates a provider that is both a websocket provider and a wallet provider.
/// note NOT type erased so we can access the wallet methods of the provider
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
        .wallet(EthereumWallet::new(
            LocalSigner::from_str(&hex::encode(private_key))
                .map_err(|e| errors::RiftSdkError::InvalidPrivateKey(e.to_string()))?,
        ))
        .on_client(client);

    Ok(provider)
}

pub fn handle_background_thread_result<T>(
    result: Option<Result<Result<T, eyre::Report>, tokio::task::JoinError>>,
) -> eyre::Result<()> {
    match result {
        Some(Ok(thread_result)) => match thread_result {
            Ok(_) => Err(eyre::eyre!("Background thread completed unexpectedly")),
            Err(e) => Err(eyre::eyre!("Background thread panicked: {}", e)),
        },
        Some(Err(e)) => Err(eyre::eyre!("Join set failed: {}", e)),
        None => Err(eyre::eyre!("Join set panicked with no result")),
    }
}
