//! `lib.rs` — central library code.

pub mod bitcoin_devnet;
pub mod evm_devnet;

use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use bitcoin_data_engine::BitcoinDataEngine;
pub use bitcoin_devnet::BitcoinDevnet;
pub use evm_devnet::EthDevnet;

use evm_devnet::ForkConfig;
use eyre::Result;
use log::info;
use sol_bindings::RiftExchange;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::task::JoinSet;
use tokio::time::Instant;

use data_engine::engine::ContractDataEngine;
use data_engine_server::DataEngineServer;

use rift_sdk::{get_rift_program_hash, DatabaseLocation, WebsocketWalletProvider};

use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::RpcApi;
use rift_sdk::bitcoin_utils::{AsyncBitcoinClient, BitcoinClientExt};

// ================== Contract ABIs ================== //

const TOKEN_ADDRESS: &str = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf";
const TOKEN_SYMBOL: &str = "cbBTC";
const TOKEN_NAME: &str = "Coinbase Wrapped BTC";
const TOKEN_DECIMALS: u8 = 8;
const CONTRACT_DATA_ENGINE_SERVER_PORT: u16 = 50100;

use alloy::sol;

/// The mock token artifact
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MockToken,
    "../../contracts/artifacts/MockToken.json"
);

/// The SP1 mock verifier
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SP1MockVerifier,
    "../../contracts/artifacts/SP1MockVerifier.json"
);

use alloy::network::{Ethereum, EthereumWallet, NetworkWallet};
use alloy::primitives::{Address as EvmAddress, U256};
use alloy::providers::{Identity, Provider, RootProvider};
use alloy::pubsub::PubSubFrontend;

pub type RiftExchangeWebsocket =
    RiftExchange::RiftExchangeInstance<PubSubFrontend, Arc<WebsocketWalletProvider>>;

pub type MockTokenWebsocket =
    MockToken::MockTokenInstance<PubSubFrontend, Arc<WebsocketWalletProvider>>;

// ================== Deploy Function ================== //

use alloy::{node_bindings::AnvilInstance, signers::Signer};

/// Deploy all relevant contracts: RiftExchange & MockToken
/// Return `(RiftExchange, MockToken, deployment_block_number)`.
pub async fn deploy_contracts(
    anvil: &AnvilInstance,
    circuit_verification_key_hash: [u8; 32],
    genesis_mmr_root: [u8; 32],
    tip_block_leaf: BlockLeaf,
    on_fork: bool,
) -> Result<(Arc<RiftExchangeWebsocket>, Arc<MockTokenWebsocket>, u64)> {
    use alloy::{
        hex::FromHex,
        primitives::Address,
        providers::{ext::AnvilApi, ProviderBuilder, WsConnect},
        signers::local::PrivateKeySigner,
    };
    use eyre::eyre;
    use std::str::FromStr;

    let deployer_signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let deployer_wallet = EthereumWallet::from(deployer_signer.clone());
    let deployer_address = deployer_wallet.default_signer().address();

    // Build a provider
    let provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(deployer_wallet)
            .on_ws(WsConnect::new(anvil.ws_endpoint_url()))
            .await
            .map_err(|e| eyre!("Error connecting to Anvil: {e}"))?,
    );

    let verifier_contract = Address::from_str("0xaeE21CeadF7A03b3034DAE4f190bFE5F861b6ebf")?;
    // Insert the SP1MockVerifier bytecode
    provider
        .anvil_set_code(verifier_contract, SP1MockVerifier::BYTECODE.clone())
        .await?;

    let token_address = EvmAddress::from_str(TOKEN_ADDRESS)?;
    // Deploy the mock token, this is dependent on if we're on a fork or not
    let token = if !on_fork {
        // deploy it
        let mock_token = MockToken::deploy(
            provider.clone(),
            TOKEN_NAME.to_string(),
            TOKEN_SYMBOL.to_string(),
            TOKEN_DECIMALS,
        )
        .await?;
        provider
            .anvil_set_code(
                token_address,
                provider.get_code_at(*mock_token.address()).await?,
            )
            .await?;
        MockToken::new(token_address, provider.clone())
    } else {
        MockToken::new(token_address, provider.clone())
    };

    // Record the block number to track from
    let deployment_block_number = provider.get_block_number().await?;

    let tip_block_leaf_sol: sol_bindings::Types::BlockLeaf = tip_block_leaf.into();
    // Deploy RiftExchange
    let exchange = RiftExchange::deploy(
        provider.clone(),
        genesis_mmr_root.into(),
        *token.address(),
        circuit_verification_key_hash.into(),
        verifier_contract,
        deployer_address, // e.g. owner
        tip_block_leaf_sol,
    )
    .await?;

    Ok((Arc::new(exchange), Arc::new(token), deployment_block_number))
}

// ================== RiftDevnet ================== //

/// The "combined" Devnet which holds:
/// - a `BitcoinDevnet`
/// - an `EthDevnet`
/// - a `DataEngine` (for your chain indexing)
/// - an optional `DataEngineServer`
pub struct RiftDevnet {
    pub bitcoin: BitcoinDevnet,
    pub ethereum: EthDevnet,
    pub contract_data_engine: Arc<ContractDataEngine>,
    pub checkpoint_file_path: String,
    pub join_set: JoinSet<eyre::Result<()>>,
    checkpoint_file_handle: NamedTempFile,
    data_engine_server: Option<DataEngineServer>,
}

impl RiftDevnet {
    pub fn builder() -> RiftDevnetBuilder {
        RiftDevnetBuilder::default()
    }
}

/// A builder for configuring a `RiftDevnet` instantiation.
pub struct RiftDevnetBuilder {
    interactive: bool,
    using_bitcoin: bool,
    funded_evm_address: Option<String>,
    funded_bitcoin_address: Option<String>,
    fork_config: Option<ForkConfig>,
    data_engine_db_location: DatabaseLocation,
}

impl Default for RiftDevnetBuilder {
    fn default() -> Self {
        Self {
            interactive: false,
            using_bitcoin: true,
            funded_evm_address: None,
            funded_bitcoin_address: None,
            fork_config: None,
            data_engine_db_location: DatabaseLocation::InMemory,
        }
    }
}

impl RiftDevnetBuilder {
    /// Create a new builder with all default values.
    pub fn new() -> Self {
        Default::default()
    }

    /// Toggle whether the devnet runs in "interactive" mode:
    /// - If true, binds Anvil on a stable port and starts a local DataEngineServer.
    /// - If false, does minimal ephemeral setup.
    pub fn interactive(mut self, value: bool) -> Self {
        self.interactive = value;
        self
    }

    /// If `false`, the devnet only mines 1 Bitcoin block instead of 101,
    /// avoiding full Bitcoin usage for speed. Defaults to `true`.
    pub fn using_bitcoin(mut self, value: bool) -> Self {
        self.using_bitcoin = value;
        self
    }

    /// Optionally fund a given EVM address with Ether and tokens.
    pub fn funded_evm_address<T: Into<String>>(mut self, address: T) -> Self {
        self.funded_evm_address = Some(address.into());
        self
    }

    /// Optionally fund a given Bitcoin address.
    pub fn funded_bitcoin_address<T: Into<String>>(mut self, address: T) -> Self {
        self.funded_bitcoin_address = Some(address.into());
        self
    }

    /// Provide a fork configuration (RPC URL/block) if you want to fork a public chain.
    pub fn fork_config(mut self, config: ForkConfig) -> Self {
        self.fork_config = Some(config);
        self
    }

    /// Location of the DataEngine’s database — defaults to in-memory.
    pub fn data_engine_db_location(mut self, loc: DatabaseLocation) -> Self {
        self.data_engine_db_location = loc;
        self
    }

    /// Actually build the `RiftDevnet`, consuming this builder.
    ///
    /// Returns a tuple of:
    ///   - The devnet instance
    ///   - The number of satoshis funded to `funded_bitcoin_address` (if any)
    pub async fn build(self) -> Result<(crate::RiftDevnet, u64)> {
        // All logic is adapted from the old `RiftDevnet::setup`.
        let Self {
            interactive,
            using_bitcoin,
            funded_evm_address,
            funded_bitcoin_address,
            fork_config,
            data_engine_db_location,
        } = self;

        let mut join_set = JoinSet::new();

        // 1) Bitcoin side
        let (bitcoin_devnet, current_mined_height) = crate::bitcoin_devnet::BitcoinDevnet::setup(
            funded_bitcoin_address,
            using_bitcoin,
            &mut join_set,
        )
        .await?;
        let funding_sats = bitcoin_devnet.funded_sats;

        // 2) Collect Bitcoin checkpoint leaves
        log::info!(
            "Downloading checkpoint leaves from block range 0..{}",
            current_mined_height
        );
        let checkpoint_leaves = bitcoin_devnet
            .rpc_client
            .get_leaves_from_block_range(0, current_mined_height, 100, None)
            .await?;

        // 3) Save compressed leaves to a named temp file
        let named_temp_file = tempfile::NamedTempFile::new()?;
        let output_file_path = named_temp_file.path().to_string_lossy().to_string();
        checkpoint_downloader::compress_checkpoint_leaves(
            &checkpoint_leaves,
            output_file_path.as_str(),
        )?;
        let tip_block_leaf = checkpoint_leaves.last().unwrap().clone();

        // 4) Create/seed DataEngine
        log::info!("Seeding data engine with checkpoint leaves...");
        let t = tokio::time::Instant::now();
        let mut contract_data_engine = data_engine::engine::ContractDataEngine::seed(
            &data_engine_db_location,
            checkpoint_leaves,
        )
        .await?;
        log::info!("Data engine seeded in {:?}", t.elapsed());

        // 5) Ethereum side
        let circuit_verification_key_hash = rift_sdk::get_rift_program_hash();
        let (ethereum_devnet, deployment_block_number) = crate::evm_devnet::EthDevnet::setup(
            circuit_verification_key_hash,
            contract_data_engine.get_mmr_root().await.unwrap(),
            tip_block_leaf,
            fork_config,
            interactive,
        )
        .await?;

        // 6) Start listening to on-chain events
        contract_data_engine
            .start_event_listener(
                ethereum_devnet.funded_provider.clone(),
                *ethereum_devnet.rift_exchange_contract.address(),
                deployment_block_number,
                &mut join_set,
            )
            .await?;

        // 7) Wait for initial sync
        let contract_data_engine = std::sync::Arc::new(contract_data_engine);
        println!("Waiting for contract data engine initial sync...");
        let t = tokio::time::Instant::now();
        contract_data_engine.wait_for_initial_sync().await?;
        println!(
            "Contract data engine initial sync complete in {:?}",
            t.elapsed()
        );

        // 8) Possibly run data-engine server in interactive mode
        let contract_data_engine_server = if interactive {
            Some(
                data_engine_server::DataEngineServer::from_engine(
                    contract_data_engine.clone(),
                    crate::CONTRACT_DATA_ENGINE_SERVER_PORT,
                    &mut join_set,
                )
                .await?,
            )
        } else {
            None
        };

        // 9) Fund optional EVM address with Ether + tokens
        if let Some(addr_str) = funded_evm_address {
            use alloy::primitives::Address;
            use std::str::FromStr;
            let address = Address::from_str(&addr_str)?;

            // ~10 ETH
            ethereum_devnet
                .fund_eth_address(
                    address,
                    alloy::primitives::U256::from_str("10000000000000000000")?,
                )
                .await?;

            // ~10 tokens with 18 decimals
            ethereum_devnet
                .mint_token(
                    address,
                    alloy::primitives::U256::from_str("10000000000000000000")?,
                )
                .await?;

            // Debugging: check funded balances
            let eth_balance = ethereum_devnet.funded_provider.get_balance(address).await?;
            println!("Ether Balance of {} => {:?}", addr_str, eth_balance);
            let token_balance = ethereum_devnet
                .token_contract
                .balanceOf(address)
                .call()
                .await?
                ._0;
            println!("Token Balance of {} => {:?}", addr_str, token_balance);
        }

        // 10) Log interactive info
        if interactive {
            println!("---RIFT DEVNET---");
            println!(
                "Anvil HTTP Url:        http://0.0.0.0:{}",
                ethereum_devnet.anvil.port()
            );
            println!(
                "Anvil WS Url:          ws://0.0.0.0:{}",
                ethereum_devnet.anvil.port()
            );
            println!(
                "Anvil Chain ID:        {}",
                ethereum_devnet.anvil.chain_id()
            );
            println!(
                "Data Engine HTTP URL:  http://0.0.0.0:{}",
                crate::CONTRACT_DATA_ENGINE_SERVER_PORT
            );
            println!(
                "Bitcoin RPC URL:       {}",
                bitcoin_devnet.rpc_url_with_cookie
            );
            println!(
                "{} Address:  {}",
                crate::TOKEN_SYMBOL,
                ethereum_devnet.token_contract.address()
            );
            println!(
                "{} Address:  {}",
                "Rift Exchange",
                ethereum_devnet.rift_exchange_contract.address()
            );
            println!("---RIFT DEVNET---");
        }

        // 11) Return the final devnet
        let devnet = crate::RiftDevnet {
            bitcoin: bitcoin_devnet,
            ethereum: ethereum_devnet,
            contract_data_engine,
            checkpoint_file_path: output_file_path,
            join_set,
            data_engine_server: contract_data_engine_server,
            checkpoint_file_handle: named_temp_file,
        };

        Ok((devnet, funding_sats))
    }
}
