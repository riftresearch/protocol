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
use tokio::time::Instant;

use data_engine::engine::DataEngine;
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
    pub contract_data_engine: Arc<DataEngine>,
    pub _data_engine_server: Option<DataEngineServer>,
    pub checkpoint_file_path: String,
}

impl RiftDevnet {
    /// The main entry point to set up a devnet with both sides plus data engine.
    /// Returns `(RiftDevnet, funding_sats)`.
    pub async fn setup(
        interactive: bool,
        // If not actually using bitcoin, we can only mine a single block instead of the standard 101
        // which speeds up the setup
        using_bitcoin: bool,
        funded_evm_address: Option<String>,
        funded_bitcoin_address: Option<String>,
        fork_config: Option<ForkConfig>,
        data_engine_db_location: DatabaseLocation,
    ) -> Result<(Self, u64)> {
        println!("Setting up RiftDevnet...");
        // 1) Bitcoin side
        let (bitcoin_devnet, current_mined_height) =
            BitcoinDevnet::setup(funded_bitcoin_address, using_bitcoin).await?;
        let funding_sats = bitcoin_devnet.funded_sats;

        // 2) Grab some additional info (like checkpoint leaves)
        info!("Downloading checkpoint leaves from block range 0..101");
        let checkpoint_leaves = bitcoin_devnet
            .rpc_client
            .get_leaves_from_block_range(0, current_mined_height, 100, None)
            .await?;

        let named_temp_file = tempfile::NamedTempFile::new()?;
        let output_file_path = named_temp_file.path().to_string_lossy().to_string();

        checkpoint_downloader::compress_checkpoint_leaves(
            &checkpoint_leaves,
            output_file_path.as_str(),
        )?;

        let tip_block_leaf = &checkpoint_leaves.last().unwrap().clone();

        // 4) Data Engine
        info!("Seeding data engine with checkpoint leaves...");
        let t = Instant::now();
        let mut contract_data_engine =
            DataEngine::seed(&data_engine_db_location, checkpoint_leaves).await?;
        info!("Data engine seeded in {:?}", t.elapsed());

        // 3) Start EVM side
        let circuit_verification_key_hash = get_rift_program_hash();
        let (ethereum_devnet, deployment_block_number) = EthDevnet::setup(
            circuit_verification_key_hash,
            contract_data_engine.get_mmr_root().await.unwrap(),
            *tip_block_leaf,
            fork_config,
            interactive,
        )
        .await?;

        // Start listening for on-chain events from RiftExchange
        contract_data_engine
            .start_event_listener(
                ethereum_devnet.funded_provider.clone(),
                ethereum_devnet.rift_exchange_contract.address().to_string(),
                deployment_block_number,
            )
            .await?;

        let contract_data_engine = Arc::new(contract_data_engine);
        println!("Waiting for contract data engine initial sync...");
        let t = Instant::now();
        contract_data_engine.wait_for_initial_sync().await?;
        println!(
            "Contract data engine initial sync complete in {:?}",
            t.elapsed()
        );

        // Possibly run a local data-engine HTTP server
        let contract_data_engine_server = if interactive {
            let server = DataEngineServer::from_engine(
                contract_data_engine.clone(),
                CONTRACT_DATA_ENGINE_SERVER_PORT,
            )
            .await?;
            Some(server)
        } else {
            None
        };

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
                CONTRACT_DATA_ENGINE_SERVER_PORT
            );
            println!(
                "Bitcoin RPC URL:       {}",
                bitcoin_devnet.regtest.rpc_url()
            );
            println!(
                "{} Address:  {}",
                TOKEN_SYMBOL,
                ethereum_devnet.token_contract.address()
            );
            println!(
                "{} Address:  {}",
                "Rift Exchange",
                ethereum_devnet.rift_exchange_contract.address()
            );
            println!("---RIFT DEVNET---");
        }

        // If we want to fund an EVM address
        if let Some(addr_str) = funded_evm_address {
            use alloy::primitives::Address;
            use std::str::FromStr;

            let address = Address::from_str(&addr_str)?;
            // Fund with ~100 ETH
            ethereum_devnet
                .fund_eth_address(address, U256::from_str("10000000000000000000")?)
                .await?;

            // Fund with e.g. 1_000_000 tokens
            ethereum_devnet
                .mint_token(address, U256::from_str("10000000000000000000")?)
                .await?;

            // get the balance of the funded address
            let balance = ethereum_devnet.funded_provider.get_balance(address).await?;
            println!("Ether Balance: {:?}", balance);
            let token_balance = ethereum_devnet
                .token_contract
                .balanceOf(address)
                .call()
                .await?
                ._0;
            println!("Token Balance: {:?}", token_balance);
        }

        // Build final devnet
        let devnet = Self {
            bitcoin: bitcoin_devnet,
            ethereum: ethereum_devnet,
            contract_data_engine,
            _data_engine_server: contract_data_engine_server,
            checkpoint_file_path: output_file_path,
        };

        Ok((devnet, funding_sats))
    }
}
