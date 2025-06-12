//! `lib.rs` — central library code.

pub mod bitcoin_devnet;
mod devnet_lock;
pub mod evm_devnet;

pub use bitcoin_devnet::BitcoinDevnet;
pub use evm_devnet::EthDevnet;

use evm_devnet::ForkConfig;
use eyre::Result;
use rift_sdk::proof_generator::ProofGeneratorType;
use sol_bindings::RiftExchangeHarnessInstance;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::task::JoinSet;

use data_engine::engine::ContractDataEngine;
use data_engine_server::DataEngineServer;

use rift_sdk::{create_websocket_wallet_provider, DatabaseLocation, MultichainAccount};

use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::RpcApi;
use rift_sdk::bitcoin_utils::BitcoinClientExt;

// ================== Contract ABIs ================== //

const TOKEN_ADDRESS: &str = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf";
const TOKEN_SYMBOL: &str = "cbBTC";
const TOKEN_NAME: &str = "Coinbase Wrapped BTC";
const TOKEN_DECIMALS: u8 = 8;
const TAKER_FEE_BIPS: u16 = 10;
const CONTRACT_DATA_ENGINE_SERVER_PORT: u16 = 50100;

use alloy::{hex, sol};

/// The mock token artifact
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SyntheticBTC,
    "../../contracts/artifacts/SyntheticBTC.json"
);

/// The SP1 mock verifier
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SP1MockVerifier,
    "../../contracts/artifacts/SP1MockVerifier.json"
);

use alloy::network::EthereumWallet;
use alloy::primitives::Address as EvmAddress;
use alloy::providers::{DynProvider, Provider};

pub type RiftExchangeHarnessWebsocket = RiftExchangeHarnessInstance<DynProvider>;

pub type SyntheticBTCWebsocket = SyntheticBTC::SyntheticBTCInstance<DynProvider>;

// ================== Deploy Function ================== //

use alloy::{node_bindings::AnvilInstance, signers::Signer};

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
    funded_evm_addresses: Vec<String>,
    funded_bitcoin_addreses: Vec<String>,
    fork_config: Option<ForkConfig>,
    data_engine_db_location: DatabaseLocation,
    log_chunk_size: u64,
    using_esplora: bool,
}

impl Default for RiftDevnetBuilder {
    fn default() -> Self {
        Self {
            interactive: false,
            using_bitcoin: true,
            funded_evm_addresses: vec![],
            funded_bitcoin_addreses: vec![],
            fork_config: None,
            data_engine_db_location: DatabaseLocation::InMemory,
            log_chunk_size: 10000,
            using_esplora: false,
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
        self.funded_evm_addresses.push(address.into());
        self
    }

    /// Optionally fund a given Bitcoin address.
    pub fn funded_bitcoin_address<T: Into<String>>(mut self, address: T) -> Self {
        self.funded_bitcoin_addreses.push(address.into());
        self
    }

    /// Provide a fork configuration (RPC URL/block) if you want to fork a public chain.
    pub fn fork_config(mut self, config: ForkConfig) -> Self {
        self.fork_config = Some(config);
        self
    }

    /// Location of the DataEngine's database — defaults to in-memory.
    pub fn data_engine_db_location(mut self, loc: DatabaseLocation) -> Self {
        self.data_engine_db_location = loc;
        self
    }

    /// Start a blockstream/electrs esplora REST API server for bitcoin data indexing.
    pub fn using_esplora(mut self, value: bool) -> Self {
        self.using_esplora = value;
        self
    }

    /// Actually build the `RiftDevnet`, consuming this builder.
    ///
    /// Returns a tuple of:
    ///   - The devnet instance
    ///   - The number of satoshis funded to `funded_bitcoin_address` (if any)
    pub async fn build(self) -> Result<(crate::RiftDevnet, u64)> {
        // 0) ───── Serialise the BUILD *only* ─────
        let _build_lock = crate::devnet_lock::DevnetBuildGuard::acquire().await?;

        // All logic is adapted from the old `RiftDevnet::setup`.
        let Self {
            interactive,
            using_bitcoin,
            funded_evm_addresses,
            funded_bitcoin_addreses,
            fork_config,
            data_engine_db_location,
            log_chunk_size,
            using_esplora,
        } = self;

        let mut join_set = JoinSet::new();

        // 1) Bitcoin side
        let (bitcoin_devnet, current_mined_height) = crate::bitcoin_devnet::BitcoinDevnet::setup(
            funded_bitcoin_addreses,
            using_bitcoin,
            using_esplora,
            interactive,
            &mut join_set,
        )
        .await
        .map_err(|e| eyre::eyre!("[devnet builder] Failed to setup Bitcoin devnet: {}", e))?;

        // Drop build lock here, only really necessary for bitcoin devnet setup
        let funding_sats = bitcoin_devnet.funded_sats;

        // 2) Collect Bitcoin checkpoint leaves
        log::info!(
            "Downloading checkpoint leaves from block range 0..{}",
            current_mined_height
        );
        let checkpoint_leaves = bitcoin_devnet
            .rpc_client
            .get_leaves_from_block_range(0, current_mined_height, 100, None)
            .await
            .map_err(|e| eyre::eyre!("[devnet builder] Failed to get checkpoint leaves: {}", e))?;

        // 3) Save compressed leaves to a named temp file
        let named_temp_file = tempfile::NamedTempFile::new()?;
        let output_file_path = named_temp_file.path().to_string_lossy().to_string();
        checkpoint_downloader::compress_checkpoint_leaves(
            &checkpoint_leaves,
            output_file_path.as_str(),
        )
        .map_err(|e| {
            eyre::eyre!(
                "[devnet builder] Failed to compress checkpoint leaves: {}",
                e
            )
        })?;
        let tip_block_leaf = checkpoint_leaves.last().unwrap().clone();

        // 4) Create/seed DataEngine
        log::info!("Seeding data engine with checkpoint leaves...");
        let t = tokio::time::Instant::now();
        let mut contract_data_engine = data_engine::engine::ContractDataEngine::seed(
            &data_engine_db_location,
            checkpoint_leaves,
        )
        .await
        .map_err(|e| eyre::eyre!("[devnet builder] Failed to seed data engine: {}", e))?;
        log::info!("Data engine seeded in {:?}", t.elapsed());

        // 5) Ethereum side
        let circuit_verification_key_hash = rift_sdk::get_rift_program_hash();
        let (ethereum_devnet, deployment_block_number) = crate::evm_devnet::EthDevnet::setup(
            circuit_verification_key_hash,
            contract_data_engine
                .get_mmr_root()
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to get MMR root: {}", e))?,
            tip_block_leaf,
            fork_config,
            interactive,
        )
        .await
        .map_err(|e| eyre::eyre!("[devnet builder] Failed to setup Ethereum devnet: {}", e))?;

        // 6) Start listening to on-chain events
        contract_data_engine
            .start_event_listener(
                ethereum_devnet.funded_provider.clone(),
                *ethereum_devnet.rift_exchange_contract.address(),
                deployment_block_number,
                log_chunk_size,
                &mut join_set,
            )
            .await
            .map_err(|e| eyre::eyre!("[devnet builder] Failed to start event listener: {}", e))?;

        // 7) Wait for initial sync
        let contract_data_engine = std::sync::Arc::new(contract_data_engine);
        println!("Waiting for contract data engine initial sync...");
        let t = tokio::time::Instant::now();
        contract_data_engine
            .wait_for_initial_sync()
            .await
            .map_err(|e| eyre::eyre!("[devnet builder] Failed to wait for initial sync: {}", e))?;
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
                .await
                .map_err(|e| {
                    eyre::eyre!("[devnet builder] Failed to start data engine server: {}", e)
                })?,
            )
        } else {
            None
        };

        // 9) Fund optional EVM address with Ether + tokens
        for addr_str in funded_evm_addresses {
            use alloy::primitives::Address;
            use std::str::FromStr;
            let address = Address::from_str(&addr_str)?; // TODO: check if this is correct

            // ~10 ETH
            ethereum_devnet
                .fund_eth_address(
                    address,
                    alloy::primitives::U256::from_str("10000000000000000000")?,
                )
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to fund ETH address: {}", e))?;

            // ~10 tokens with 18 decimals
            ethereum_devnet
                .mint_token(
                    address,
                    alloy::primitives::U256::from_str("10000000000000000000")?,
                )
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to mint token: {}", e))?;

            // Debugging: check funded balances
            let eth_balance = ethereum_devnet
                .funded_provider
                .get_balance(address)
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to get ETH balance: {}", e))?;
            println!("Ether Balance of {} => {:?}", addr_str, eth_balance);
            let token_balance = ethereum_devnet
                .token_contract
                .balanceOf(address)
                .call()
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to get token balance: {}", e))?;
            println!("Token Balance of {} => {:?}", addr_str, token_balance);
        }

        let hypernode_account = MultichainAccount::new(151);
        let market_maker_account = MultichainAccount::new(152);

        // 10) Start hypernode and market maker if in interactive mode
        let (hypernode, market_maker) = if interactive {
            ethereum_devnet
                .fund_eth_address(
                    hypernode_account.ethereum_address,
                    alloy::primitives::U256::from_str_radix("1000000000000000000000000", 10)?,
                )
                .await
                .map_err(|e| {
                    eyre::eyre!(
                        "[devnet builder-hypernode] Failed to fund ETH address: {}",
                        e
                    )
                })?;

            ethereum_devnet
                .fund_eth_address(
                    market_maker_account.ethereum_address,
                    alloy::primitives::U256::from_str_radix("1000000000000000000000000", 10)?,
                )
                .await
                .map_err(|e| {
                    eyre::eyre!(
                        "[devnet builder-market_maker] Failed to fund ETH address: {}",
                        e
                    )
                })?;

            bitcoin_devnet
                .deal_bitcoin(
                    market_maker_account.bitcoin_wallet.address.clone(),
                    bitcoin::Amount::from_btc(100.0).unwrap(),
                )
                .await
                .map_err(|e| {
                    eyre::eyre!(
                        "[devnet builder-market_maker] Failed to deal bitcoin: {}",
                        e
                    )
                })?;

            // Start hypernode
            let hypernode_args = hypernode::HypernodeArgs {
                evm_ws_rpc: ethereum_devnet.anvil.ws_endpoint_url().to_string(),
                btc_rpc: bitcoin_devnet.rpc_url_with_cookie.clone(),
                private_key: hex::encode(hypernode_account.secret_bytes),
                checkpoint_file: output_file_path.clone(),
                database_location: data_engine_db_location.clone(),
                rift_exchange_address: ethereum_devnet.rift_exchange_contract.address().to_string(),
                deploy_block_number: deployment_block_number,
                log_chunk_size,
                btc_batch_rpc_size: 100,
                proof_generator: ProofGeneratorType::Execute,
            };

            let hypernode_handle = join_set.spawn(async move {
                hypernode_args
                    .run()
                    .await
                    .map_err(|e| eyre::eyre!("Hypernode failed: {}", e))
            });

            // Start market maker if mnemonic is provided
            let market_maker_handle = {
                let maker_config = market_maker::MakerConfig {
                    evm_ws_rpc: ethereum_devnet.anvil.ws_endpoint_url().to_string(),
                    btc_rpc: bitcoin_devnet.rpc_url_with_cookie.clone(),
                    btc_rpc_timeout_ms: 10000,
                    evm_private_key: hex::encode(hypernode_account.secret_bytes),
                    btc_mnemonic: market_maker_account.bitcoin_mnemonic.to_string(),
                    btc_mnemonic_passphrase: None,
                    btc_mnemonic_derivation_path: None,
                    btc_network: bitcoin::Network::Regtest,
                    auction_house_address: ethereum_devnet
                        .rift_exchange_contract
                        .address()
                        .to_string(),
                    spread_bps: 0,
                    max_batch_size: 5,
                    btc_tx_size_vbytes: None,
                    esplora_api_url: bitcoin_devnet
                        .esplora_url
                        .clone()
                        .expect("Esplora URL is required for market maker"),
                    checkpoint_file: output_file_path.clone(),
                    database_location: data_engine_db_location.clone(),
                    deploy_block_number: deployment_block_number,
                    evm_log_chunk_size: log_chunk_size,
                    btc_batch_rpc_size: 100,
                    chain_id: ethereum_devnet.anvil.chain_id(),
                    order_delay_seconds: 5,
                    order_max_batch_size: 5,
                    order_required_confirmations: 2,
                    order_confirmation_timeout: 300,
                };

                Some(join_set.spawn(async move {
                    maker_config
                        .run()
                        .await
                        .map_err(|e| eyre::eyre!("Market Maker failed: {}", e))
                }))
            };

            (Some(hypernode_handle), market_maker_handle)
        } else {
            (None, None)
        };

        // 11) Log interactive info
        if interactive {
            let periphery = ethereum_devnet.periphery.as_ref().unwrap();
            println!("---RIFT DEVNET---");
            println!(
                "Anvil HTTP Url:             http://0.0.0.0:{}",
                ethereum_devnet.anvil.port()
            );
            println!(
                "Anvil WS Url:               ws://0.0.0.0:{}",
                ethereum_devnet.anvil.port()
            );
            println!(
                "Anvil Chain ID:             {}",
                ethereum_devnet.anvil.chain_id()
            );
            println!(
                "Data Engine HTTP URL:       http://0.0.0.0:{}",
                crate::CONTRACT_DATA_ENGINE_SERVER_PORT
            );
            println!(
                "Bitcoin RPC URL:            {}",
                bitcoin_devnet.rpc_url_with_cookie
            );

            if using_esplora {
                println!(
                    "Esplora API URL:            {}",
                    bitcoin_devnet.esplora_url.as_ref().unwrap()
                );
            }

            println!(
                "{} Address:              {}",
                crate::TOKEN_SYMBOL,
                ethereum_devnet.token_contract.address()
            );
            println!(
                "Rift Exchange Address:      {}",
                ethereum_devnet.rift_exchange_contract.address()
            );

            println!(
                "Bundler3 Address:           {}",
                periphery.bundler3.address()
            );
            println!(
                "GeneralAdapter1 Address:    {}",
                periphery.general_adapter1.address()
            );
            println!(
                "RiftAuctionAdapter Address: {}",
                periphery.rift_auction_adapter.address()
            );

            println!(
                "MM Bitcoin Address:         {}",
                market_maker_account.bitcoin_wallet.address
            );

            if hypernode.is_some() {
                println!("Hypernode:                  Running");
            }
            if market_maker.is_some() {
                println!("Market Maker:               Running");
            }

            println!("---RIFT DEVNET---");
        }

        // 12) Return the final devnet
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
