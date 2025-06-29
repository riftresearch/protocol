use std::sync::Arc;

use bitcoin_light_client_core::leaves::BlockLeaf;
use eyre::{eyre, Result};
use log::info;
use rift_sdk::create_websocket_wallet_provider;
use sol_bindings::{
    RiftAuctionAdaptor::RiftAuctionAdaptorInstance,
    RiftExchangeHarnessInstance,
};
use tokio::time::Instant;

use alloy::{
    network::TransactionBuilder,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, U256},
    providers::{ext::AnvilApi, DynProvider, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
};

use crate::{
    get_new_temp_dir, RiftDevnetCache, RiftExchangeHarnessWebsocket, SP1MockVerifier, TokenizedBTC,
    TokenizedBTCWebsocket, TAKER_FEE_BIPS, TOKEN_ADDRESS,
};

pub struct PeripheryContracts {
    pub rift_auction_adapter: Arc<RiftAuctionAdaptorInstance<DynProvider>>,
}

/// Holds all Ethereum-related devnet state.
pub struct EthDevnet {
    pub anvil: AnvilInstance,
    pub token_contract: Arc<TokenizedBTCWebsocket>,
    pub rift_exchange_contract: Arc<RiftExchangeHarnessWebsocket>,
    pub verifier_contract: Address,
    pub funded_provider: DynProvider,
    pub deploy_mode: Mode,
    pub periphery: Option<PeripheryContracts>,
    pub anvil_datadir: Option<tempfile::TempDir>,
    pub anvil_dump_path: tempfile::TempDir,
    pub deployment_block_number: u64,
}

#[derive(Clone, Debug)]
pub enum Mode {
    Fork(ForkConfig),
    Local,
}

impl EthDevnet {
    /// Spawns Anvil, deploys the EVM contracts, returns `(Self, deployment_block_number)`.
    pub async fn setup(
        circuit_verification_key_hash: [u8; 32],
        genesis_mmr_root: [u8; 32],
        tip_block_leaf: BlockLeaf,
        deploy_mode: Mode,
        devnet_cache: Option<Arc<RiftDevnetCache>>,
    ) -> Result<(Self, u64)> {
        let (anvil, anvil_datadir, anvil_dump_path) =
            spawn_anvil(deploy_mode.clone(), devnet_cache.clone()).await?;
        info!(
            "Anvil spawned at {}, chain_id={}",
            anvil.endpoint(),
            anvil.chain_id()
        );

        let private_key = anvil.keys()[0].clone().to_bytes().into();

        let funded_provider = create_websocket_wallet_provider(
            anvil.ws_endpoint_url().to_string().as_str(),
            private_key,
        )
        .await?
        .erased();

        let (rift_exchange, token_contract, verifier_contract, deployment_block_number, periphery) =
            match devnet_cache {
                Some(devnet_cache) if devnet_cache.populated => {
                    let cache_load_start = Instant::now();
                    info!("[EVM Setup] Loading cached EVM contracts...");

                    // Load contract metadata from cache
                    let metadata_path = devnet_cache.cache_dir.join("contracts.json");
                    let metadata_json = tokio::fs::read_to_string(&metadata_path).await?;
                    let metadata: crate::ContractMetadata = serde_json::from_str(&metadata_json)?;

                    // Create contract instances from cached addresses
                    let rift_exchange = Arc::new(RiftExchangeHarnessInstance::new(
                        metadata.rift_exchange_address.parse()?,
                        funded_provider.clone(),
                    ));

                    let token_contract = Arc::new(crate::TokenizedBTC::TokenizedBTCInstance::new(
                        metadata.token_address.parse()?,
                        funded_provider.clone(),
                    ));

                    let verifier_contract = metadata.verifier_address.parse()?;

                    let periphery = match (deploy_mode.clone(), metadata.periphery) {
                        (Mode::Fork(_), Some(periphery_meta)) => {
                            let rift_auction_adapter = Arc::new(RiftAuctionAdaptorInstance::new(
                                periphery_meta.rift_auction_adapter_address.parse()?,
                                funded_provider.clone(),
                            ));
                            Some(PeripheryContracts {
                                rift_auction_adapter,
                            })
                        }
                        _ => None,
                    };

                    info!("[EVM Setup] Loaded cached contracts in {:?}", cache_load_start.elapsed());
                    (
                        rift_exchange,
                        token_contract,
                        verifier_contract,
                        metadata.deployment_block_number,
                        periphery,
                    )
                }
                _ => {
                    let t = Instant::now();
                    let (rift_exchange, token_contract, verifier_contract, deployment_block_number) =
                        deploy_contracts(
                            funded_provider.clone(),
                            circuit_verification_key_hash,
                            genesis_mmr_root,
                            tip_block_leaf,
                            deploy_mode.clone(),
                        )
                        .await?;
                    info!("Deployed RiftExchange at {}", rift_exchange.address());

                    // Should only need to deploy periphery contracts if we're in interactive mode
                    let periphery = match deploy_mode.clone() {
                        Mode::Fork(fork_config) => {
                            let rift_auction_adaptor = deploy_periphery(
                                funded_provider.clone(),
                                fork_config.bundler3_address,
                                *rift_exchange.address(),
                            )
                            .await?;
                            Some(PeripheryContracts {
                                rift_auction_adapter: rift_auction_adaptor,
                            })
                        }
                        Mode::Local => None,
                    };

                    info!("Deployed in {:?}", t.elapsed());

                    (
                        rift_exchange,
                        token_contract,
                        verifier_contract,
                        deployment_block_number,
                        periphery,
                    )
                }
            };

        let devnet = EthDevnet {
            anvil,
            token_contract,
            rift_exchange_contract: rift_exchange,
            verifier_contract,
            funded_provider,
            deploy_mode,
            periphery,
            anvil_datadir,
            anvil_dump_path,
            deployment_block_number,
        };

        Ok((devnet, deployment_block_number))
    }

    /// Gives `amount_wei` of Ether to `address` (via anvil_set_balance).
    pub async fn fund_eth_address(&self, address: Address, amount_wei: U256) -> Result<()> {
        self.funded_provider
            .anvil_set_balance(address, amount_wei)
            .await?;
        Ok(())
    }

    /// Mints the mock token for `address`.
    pub async fn mint_token(&self, address: Address, amount: U256) -> Result<()> {
        let impersonate_provider = ProviderBuilder::new()
            .on_http(format!("http://localhost:{}", self.anvil.port()).parse()?);
        if matches!(self.deploy_mode, Mode::Fork(_)) {
            // 1. Get the master minter address
            let master_minter = self.token_contract.masterMinter().call().await?;

            // 2. Configure master minter with maximum minting allowance
            let max_allowance = U256::MAX;
            let configure_minter_calldata = self
                .token_contract
                .configureMinter(master_minter, max_allowance)
                .calldata()
                .clone();

            let tx = TransactionRequest::default()
                .with_from(master_minter)
                .with_to(*self.token_contract.address())
                .with_input(configure_minter_calldata.clone());

            impersonate_provider
                .anvil_impersonate_account(master_minter)
                .await?;

            impersonate_provider
                .send_transaction(tx)
                .await?
                .get_receipt()
                .await?;

            let mint_calldata = self.token_contract.mint(address, amount).calldata().clone();

            let tx = TransactionRequest::default()
                .with_from(master_minter)
                .with_to(*self.token_contract.address())
                .with_input(mint_calldata.clone());

            // 3. Mint tokens as master minter
            impersonate_provider
                .send_transaction(tx)
                .await?
                .get_receipt()
                .await?;
        } else {
            // For local devnet, directly mint tokens
            self.token_contract
                .mint(address, amount)
                .send()
                .await?
                .get_receipt()
                .await?;
        }
        Ok(())
    }
}

/// Deploy all relevant contracts: RiftExchange & MockToken
/// Return `(RiftExchange, MockToken, deployment_block_number)`.
pub async fn deploy_contracts(
    funded_provider: DynProvider,
    circuit_verification_key_hash: [u8; 32],
    genesis_mmr_root: [u8; 32],
    tip_block_leaf: BlockLeaf,
    mode: Mode,
) -> Result<(
    Arc<RiftExchangeHarnessWebsocket>,
    Arc<TokenizedBTCWebsocket>,
    alloy::primitives::Address,
    u64,
)> {
    let contracts_start = Instant::now();
    use alloy::{primitives::Address, providers::ext::AnvilApi};

    use std::str::FromStr;

    let verifier_contract = Address::from_str("0xaeE21CeadF7A03b3034DAE4f190bFE5F861b6ebf")?;
    // Insert the SP1MockVerifier bytecode
    funded_provider
        .anvil_set_code(verifier_contract, SP1MockVerifier::BYTECODE.clone())
        .await?;

    let token_address = Address::from_str(TOKEN_ADDRESS)?;
    // Deploy the mock token, this is dependent on if we're on a fork or not
    let token = if matches!(mode, Mode::Fork(_)) {
        // deploy it
        let mock_token = TokenizedBTC::deploy(funded_provider.clone()).await?;
        funded_provider
            .anvil_set_code(
                token_address,
                funded_provider.get_code_at(*mock_token.address()).await?,
            )
            .await?;
        TokenizedBTC::new(token_address, funded_provider.clone().erased())
    } else {
        TokenizedBTC::deploy(funded_provider.clone().erased()).await?
    };

    // Record the block number to track from
    let deployment_block_number = funded_provider.get_block_number().await?;

    let tip_block_leaf_sol: sol_bindings::BlockLeaf = tip_block_leaf.into();
    info!("[EVM Deploy] Deploying RiftExchange");
    // Deploy RiftExchange
    let exchange_start = Instant::now();
    let exchange = RiftExchangeHarnessInstance::deploy(
        funded_provider.clone().erased(),
        genesis_mmr_root.into(),
        *token.address(),
        circuit_verification_key_hash.into(),
        verifier_contract,
        verifier_contract, // arbitrary address, not used
        TAKER_FEE_BIPS,
        tip_block_leaf_sol,
    )
    .await?;
    info!("[EVM Deploy] RiftExchange deployment took {:?}", exchange_start.elapsed());

    // Add common hypernode addresses used in tests and devnet
    let hypernode_start = Instant::now();
    use alloy::signers::local::LocalSigner;
    use rift_sdk::MultichainAccount;

    // Add test hypernode accounts as authorized hypernodes
    let mut test_hypernodes = vec![
        MultichainAccount::new(2).ethereum_address, // Used in hypernode_test.rs
        MultichainAccount::new(3).ethereum_address, // Used in market_maker_hypernode_e2e_test.rs
        MultichainAccount::new(151).ethereum_address, // Used in devnet interactive mode
    ];

    // Add addresses from devnet_test.rs that submit payment proofs
    let maker_secret_bytes: [u8; 32] = [0x01; 32];
    let taker_secret_bytes: [u8; 32] = [0x02; 32];
    let maker_signer = LocalSigner::from_bytes(&maker_secret_bytes.into()).unwrap();
    let taker_signer = LocalSigner::from_bytes(&taker_secret_bytes.into()).unwrap();
    test_hypernodes.push(maker_signer.address()); // Used in test_simulated_swap_end_to_end
    test_hypernodes.push(taker_signer.address()); // Used in test_simulated_swap_end_to_end

    let hypernode_count = test_hypernodes.len();
    for hypernode_address in test_hypernodes {
        let add_hypernode_call = exchange.addHypernode(hypernode_address);
        funded_provider
            .send_transaction(add_hypernode_call.into_transaction_request())
            .await?
            .get_receipt()
            .await?;
    }
    info!("[EVM Deploy] Added {} hypernodes in {:?}", hypernode_count, hypernode_start.elapsed());

    info!("[EVM Deploy] Total contract deployment took {:?}", contracts_start.elapsed());
    Ok((
        Arc::new(exchange),
        Arc::new(token),
        verifier_contract,
        deployment_block_number,
    ))
}

/// Deploy all periphery contracts: Bundler3, GeneralAdapter1, RiftAuctionAdaptor, ParaswapAdapter
/// Return `(Bundler3, GeneralAdapter1, RiftAuctionAdaptor, ParaswapAdapter)`.
pub async fn deploy_periphery(
    funded_provider: DynProvider,
    bundler3_address: Address,
    rift_exchange_address: Address,
) -> Result<Arc<RiftAuctionAdaptorInstance<DynProvider>>> {
    let deploy_start = Instant::now();
    info!("[EVM Deploy] Deploying RiftAuctionAdaptor...");
    let rift_auction_adaptor = RiftAuctionAdaptorInstance::deploy(
        funded_provider.clone(),
        bundler3_address,
        rift_exchange_address,
    )
    .await?;
    info!("[EVM Deploy] RiftAuctionAdaptor deployed in {:?}", deploy_start.elapsed());
    Ok(Arc::new(rift_auction_adaptor))
}

#[derive(Clone, Debug)]
pub struct ForkConfig {
    pub url: String,
    pub block_number: Option<u64>,
    pub bundler3_address: Address,
}

/// Spawns Anvil in a blocking task.
async fn spawn_anvil(
    mode: Mode,
    devnet_cache: Option<Arc<RiftDevnetCache>>,
) -> Result<(AnvilInstance, Option<tempfile::TempDir>, tempfile::TempDir)> {
    let spawn_start = Instant::now();
    // Create or load anvil datafile
    let anvil_datadir = if devnet_cache.is_some() {
        let cache_start = Instant::now();
        let datadir = Some(
            devnet_cache
                .as_ref()
                .unwrap()
                .create_anvil_datadir()
                .await?,
        );
        info!("[Anvil] Created anvil datadir from cache in {:?}", cache_start.elapsed());
        datadir
    } else {
        None
    };

    let anvil_datadir_pathbuf = anvil_datadir.as_ref().map(|dir| dir.path().to_path_buf());

    // get a directory for the --dump-state flag
    let anvil_dump_path = get_new_temp_dir()?;
    let anvil_dump_pathbuf = anvil_dump_path.path().to_path_buf();

    let anvil_instance = tokio::task::spawn_blocking(move || {
        let mut anvil = Anvil::new()
            .arg("--host")
            .arg("0.0.0.0")
            .chain_id(1337)
            .arg("--steps-tracing")
            .arg("--timestamp")
            .arg((chrono::Utc::now().timestamp() - 9 * 60 * 60).to_string()) // 9 hours ago? TODO: do we need to do this?
            .arg("--dump-state")
            .arg(anvil_dump_pathbuf.to_string_lossy().to_string());

        // Load state if file exists and has content - Anvil can handle the file format directly
        if let Some(state_path) = anvil_datadir_pathbuf {
            info!("[Anvil] Loading state from {}", state_path.to_string_lossy());
            anvil = anvil
                .arg("--load-state")
                .arg(state_path.to_string_lossy().to_string());
        }

        match mode {
            Mode::Fork(fork_config) => {
                anvil = anvil.port(50101_u16);
                anvil = anvil.fork(fork_config.url);
                anvil = anvil.block_time(1);
                if let Some(block_number) = fork_config.block_number {
                    anvil = anvil.fork_block_number(block_number);
                }
            }
            Mode::Local => {}
        }
        anvil.try_spawn().map_err(|e| {
            eprintln!("Failed to spawn Anvil: {:?}", e);
            eyre!(e)
        })
    })
    .await??;

    info!("[Anvil] Anvil spawned in {:?}", spawn_start.elapsed());

    // print the stdout of the anvil instance
    /*
    let anvil_child = anvil_instance.child_mut();
    let anvil_stdout = anvil_child.stdout.take().unwrap();

    tokio::task::spawn_blocking(move || {
        use std::io::{BufRead, BufReader};

        let stdout_reader = BufReader::new(anvil_stdout);
        for line in stdout_reader.lines().map_while(Result::ok) {
            println!("anvil stdout: {}", line);
        }
    });
    */

    Ok((anvil_instance, anvil_datadir, anvil_dump_path))
}
