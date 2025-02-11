//! `lib.rs` — central library code.

mod bitcoin;
mod evm;

use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
pub use bitcoin::BitcoinDevnet;
pub use evm::EthDevnet;

use evm::EvmWebsocketProvider;
use eyre::Result;
use log::info;
use rift_sdk::bindings::RiftExchange;
use std::sync::Arc;
use tokio::time::Instant;

use data_engine::engine::DataEngine;
use data_engine_server::DataEngineServer;

use rift_sdk::{get_rift_program_hash, DatabaseLocation};

use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::RpcApi;
use rift_sdk::bitcoin_utils::{AsyncBitcoinClient, BitcoinClientExt};

// ================== Contract ABIs ================== //

const TOKEN_SYMBOL: &str = "cbBTC";
const TOKEN_NAME: &str = "Coinbase Wrapped BTC";
const TOKEN_DECIMALS: u8 = 8;
const DATA_ENGINE_SERVER_PORT: u16 = 50100;

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
use alloy::pubsub::PubSubConnect;
use alloy::pubsub::PubSubFrontend;

pub type RiftExchangeWebsocket =
    RiftExchange::RiftExchangeInstance<PubSubFrontend, EvmWebsocketProvider>;

pub type MockTokenWebsocket = MockToken::MockTokenInstance<PubSubFrontend, EvmWebsocketProvider>;

// ================== Deploy Function ================== //

use alloy::{node_bindings::AnvilInstance, signers::Signer};

/// Deploy all relevant contracts: RiftExchange & MockToken
/// Return `(RiftExchange, MockToken, deployment_block_number)`.
pub async fn deploy_contracts(
    anvil: &AnvilInstance,
    circuit_verification_key_hash: [u8; 32],
    genesis_mmr_root: [u8; 32],
    tip_block_leaf: BlockLeaf,
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

    // Deploy the mock token
    let token = MockToken::deploy(
        provider.clone(),
        TOKEN_NAME.to_owned(),
        TOKEN_SYMBOL.to_owned(),
        TOKEN_DECIMALS,
    )
    .await?;

    // Record the block number to track from
    let deployment_block_number = provider.get_block_number().await?;

    let tip_block_leaf_sol: sol_types::Types::BlockLeaf = tip_block_leaf.into();
    // Deploy RiftExchange
    let exchange = RiftExchange::deploy(
        provider.clone(),
        genesis_mmr_root.into(),
        *token.address(),
        circuit_verification_key_hash.into(),
        verifier_contract,
        deployer_address, // e.g. owner
        // TODO: any way to not do this goofy conversion? need to deduplicate the types
        rift_sdk::bindings::Types::BlockLeaf {
            blockHash: tip_block_leaf_sol.blockHash,
            height: tip_block_leaf_sol.height,
            cumulativeChainwork: tip_block_leaf_sol.cumulativeChainwork,
        },
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
    pub data_engine: Arc<DataEngine>,
    pub _data_engine_server: Option<DataEngineServer>,
}

impl RiftDevnet {
    /// The main entry point to set up a devnet with both sides plus data engine.
    /// Returns `(RiftDevnet, funding_sats)`.
    pub async fn setup(
        interactive: bool,
        funded_evm_address: Option<String>,
        funded_bitcoin_address: Option<String>,
    ) -> Result<(Self, u64)> {
        // 1) Bitcoin side
        let (bitcoin_devnet, async_btc_rpc) = BitcoinDevnet::setup(funded_bitcoin_address)?;
        let funding_sats = bitcoin_devnet.funded_sats;

        // 2) Grab some additional info (like checkpoint leaves)
        info!("Downloading checkpoint leaves from block range 0..101");
        let checkpoint_leaves = async_btc_rpc
            .get_leaves_from_block_range(0, 101, None)
            .await?;

        let tip_block_leaf = checkpoint_leaves.last().unwrap();

        // 3) Start EVM side
        let circuit_verification_key_hash = get_rift_program_hash(); // or however you do it
        let genesis_mmr_root = [0u8; 32]; // fill with your actual root
        let (ethereum_devnet, deployment_block_number) = EthDevnet::setup(
            circuit_verification_key_hash,
            genesis_mmr_root,
            *tip_block_leaf,
        )
        .await?;

        // 4) Data Engine
        info!("Seeding data engine with checkpoint leaves...");
        let t = Instant::now();
        let mut data_engine =
            DataEngine::seed(DatabaseLocation::InMemory, checkpoint_leaves).await?;
        info!("Data engine seeded in {:?}", t.elapsed());

        // Start listening for on-chain events from RiftExchange
        data_engine
            .start_event_listener(
                ethereum_devnet.funded_provider.clone(),
                ethereum_devnet.rift_exchange_contract.address().to_string(),
                deployment_block_number,
            )
            .await?;

        let data_engine = Arc::new(data_engine);

        // Possibly run a local data-engine HTTP server
        let data_engine_server = if interactive {
            let server =
                DataEngineServer::from_engine(data_engine.clone(), DATA_ENGINE_SERVER_PORT).await?;
            Some(server)
        } else {
            None
        };

        if interactive {
            println!("---RIFT DEVNET---");
            println!(
                "Anvil HTTP Url:        {}",
                ethereum_devnet.anvil.endpoint()
            );
            println!(
                "Anvil WS Url:          {}",
                ethereum_devnet.anvil.ws_endpoint()
            );
            println!(
                "Anvil Chain ID:        {}",
                ethereum_devnet.anvil.chain_id()
            );
            println!(
                "Data Engine HTTP URL:  http://localhost:{}",
                DATA_ENGINE_SERVER_PORT
            );
            println!(
                "Bitcoin RPC URL:       {}",
                bitcoin_devnet.bitcoin_regtest.rpc_url()
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
                .fund_token(address, U256::from_str("10000000000000000000")?)
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
            data_engine,
            _data_engine_server: data_engine_server,
        };

        Ok((devnet, funding_sats))
    }
}
