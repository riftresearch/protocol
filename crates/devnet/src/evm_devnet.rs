use std::sync::Arc;

use bitcoin_light_client_core::leaves::BlockLeaf;
use eyre::{eyre, Result};
use log::info;
use rift_sdk::create_websocket_wallet_provider;
use sol_bindings::{
    Bundler3::{self, Bundler3Instance},
    GeneralAdapter1::GeneralAdapter1Instance,
    ParaswapAdapter::ParaswapAdapterInstance,
    RiftAuctionAdaptor::RiftAuctionAdaptorInstance,
    RiftExchangeHarnessInstance,
};
use tokio::time::Instant;

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, U256},
    providers::{ext::AnvilApi, DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};

use crate::{
    RiftExchangeHarnessWebsocket, SP1MockVerifier, TokenizedBTC, TokenizedBTCWebsocket,
    TAKER_FEE_BIPS, TOKEN_ADDRESS,
};

pub struct PeripheryContracts {
    pub bundler3: Arc<Bundler3Instance<DynProvider>>,
    pub general_adapter1: Arc<GeneralAdapter1Instance<DynProvider>>,
    pub rift_auction_adapter: Arc<RiftAuctionAdaptorInstance<DynProvider>>,
    pub paraswap_adapter: Arc<ParaswapAdapterInstance<DynProvider>>,
}

/// Holds all Ethereum-related devnet state.
pub struct EthDevnet {
    pub anvil: AnvilInstance,
    pub token_contract: Arc<TokenizedBTCWebsocket>,
    pub rift_exchange_contract: Arc<RiftExchangeHarnessWebsocket>,
    pub verifier_contract: Address,
    pub funded_provider: DynProvider,
    pub on_fork: bool,
    pub periphery: Option<PeripheryContracts>,
}

impl EthDevnet {
    /// Spawns Anvil, deploys the EVM contracts, returns `(Self, deployment_block_number)`.
    pub async fn setup(
        circuit_verification_key_hash: [u8; 32],
        genesis_mmr_root: [u8; 32],
        tip_block_leaf: BlockLeaf,
        fork_config: Option<ForkConfig>,
        interactive: bool,
    ) -> Result<(Self, u64)> {
        let on_fork = fork_config.is_some();
        let anvil = spawn_anvil(interactive, fork_config).await?;
        info!(
            "Anvil spawned at {}, chain_id={}",
            anvil.endpoint(),
            anvil.chain_id()
        );

        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let wallet = EthereumWallet::from(signer);

        let funded_provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_ws(WsConnect::new(anvil.ws_endpoint_url()))
            .await
            .expect("Failed connecting to anvil's WS")
            .erased();

        info!("Deploying RiftExchange & MockToken...");
        let t = Instant::now();
        let (rift_exchange, token_contract, verifier_contract, deployment_block_number) =
            deploy_contracts(
                funded_provider.clone(),
                circuit_verification_key_hash,
                genesis_mmr_root,
                tip_block_leaf,
                on_fork,
            )
            .await?;

        // Should only need to deploy periphery contracts if we're in interactive mode
        let periphery = if interactive {
            let (b3, ga1, raa, pa) =
                deploy_periphery(funded_provider.clone(), *rift_exchange.address()).await?;
            (Some(PeripheryContracts {
                bundler3: b3,
                general_adapter1: ga1,
                rift_auction_adapter: raa,
                paraswap_adapter: pa,
            }))
        } else {
            (None)
        };

        info!("Deployed in {:?}", t.elapsed());

        let devnet = EthDevnet {
            anvil,
            token_contract,
            rift_exchange_contract: rift_exchange,
            verifier_contract,
            funded_provider,
            on_fork,
            periphery,
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
        if self.on_fork {
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
    on_fork: bool,
) -> Result<(
    Arc<RiftExchangeHarnessWebsocket>,
    Arc<TokenizedBTCWebsocket>,
    alloy::primitives::Address,
    u64,
)> {
    use alloy::{primitives::Address, providers::ext::AnvilApi, signers::local::PrivateKeySigner};

    use std::str::FromStr;

    let verifier_contract = Address::from_str("0xaeE21CeadF7A03b3034DAE4f190bFE5F861b6ebf")?;
    // Insert the SP1MockVerifier bytecode
    funded_provider
        .anvil_set_code(verifier_contract, SP1MockVerifier::BYTECODE.clone())
        .await?;

    let token_address = Address::from_str(TOKEN_ADDRESS)?;
    // Deploy the mock token, this is dependent on if we're on a fork or not
    let token = if !on_fork {
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
        TokenizedBTC::new(token_address, funded_provider.clone().erased())
    };

    // Record the block number to track from
    let deployment_block_number = funded_provider.get_block_number().await?;

    let tip_block_leaf_sol: sol_bindings::BlockLeaf = tip_block_leaf.into();
    // Deploy RiftExchange
    let exchange = RiftExchangeHarnessInstance::deploy(
        funded_provider.clone().erased(),
        genesis_mmr_root.into(),
        *token.address(),
        circuit_verification_key_hash.into(),
        verifier_contract,
        verifier_contract, // arbitrary address, not used
        TAKER_FEE_BIPS as u16,
        tip_block_leaf_sol,
    )
    .await?;

    // Add common hypernode addresses used in tests and devnet
    use rift_sdk::MultichainAccount;
    use alloy::signers::local::LocalSigner;
    
    // Add test hypernode accounts as authorized hypernodes
    let mut test_hypernodes = vec![
        MultichainAccount::new(2).ethereum_address,  // Used in hypernode_test.rs
        MultichainAccount::new(3).ethereum_address,  // Used in market_maker_hypernode_e2e_test.rs  
        MultichainAccount::new(151).ethereum_address, // Used in devnet interactive mode
    ];
    
    // Add addresses from devnet_test.rs that submit payment proofs
    let maker_secret_bytes: [u8; 32] = [0x01; 32];
    let taker_secret_bytes: [u8; 32] = [0x02; 32];
    let maker_signer = LocalSigner::from_bytes(&maker_secret_bytes.into()).unwrap();
    let taker_signer = LocalSigner::from_bytes(&taker_secret_bytes.into()).unwrap();
    test_hypernodes.push(maker_signer.address());  // Used in test_simulated_swap_end_to_end
    test_hypernodes.push(taker_signer.address());  // Used in test_simulated_swap_end_to_end
    
    for hypernode_address in test_hypernodes {
        let add_hypernode_call = exchange.addHypernode(hypernode_address);
        funded_provider
            .send_transaction(add_hypernode_call.into_transaction_request())
            .await?
            .get_receipt()
            .await?;
    }

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
    rift_exchange_address: Address,
) -> Result<(
    Arc<Bundler3Instance<DynProvider>>,
    Arc<GeneralAdapter1Instance<DynProvider>>,
    Arc<RiftAuctionAdaptorInstance<DynProvider>>,
    Arc<ParaswapAdapterInstance<DynProvider>>,
)> {
    use alloy::{primitives::Address, providers::ext::AnvilApi, signers::local::PrivateKeySigner};

    use std::str::FromStr;

    // These theoretically shouldn't be accessed when using devnet, so mock them
    let mock_morpho_address = Address::from_str("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead")?;
    let mock_weth_address = Address::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")?;
    let mock_augustus_registry = Address::from_str("0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")?;

    let bundler3 = Bundler3Instance::deploy(funded_provider.clone()).await?;
    let general_adapter1 = GeneralAdapter1Instance::deploy(
        funded_provider.clone(),
        *bundler3.address(),
        mock_morpho_address,
        mock_weth_address,
    )
    .await?;

    let rift_auction_adaptor = RiftAuctionAdaptorInstance::deploy(
        funded_provider.clone(),
        *bundler3.address(),
        rift_exchange_address,
    )
    .await?;

    let paraswap_adapter = ParaswapAdapterInstance::deploy(
        funded_provider.clone(),
        *bundler3.address(),
        mock_morpho_address,
        mock_augustus_registry,
    )
    .await?;

    Ok((
        Arc::new(bundler3),
        Arc::new(general_adapter1),
        Arc::new(rift_auction_adaptor),
        Arc::new(paraswap_adapter),
    ))
}

pub struct ForkConfig {
    pub url: String,
    pub block_number: Option<u64>,
}

/// Spawns Anvil in a blocking task.
async fn spawn_anvil(interactive: bool, fork_config: Option<ForkConfig>) -> Result<AnvilInstance> {
    tokio::task::spawn_blocking(move || {
        let mut anvil = Anvil::new()
            .arg("--host")
            .arg("0.0.0.0")
            .block_time(1)
            .chain_id(1337)
            .arg("--steps-tracing")
            .arg("--timestamp")
            .arg((chrono::Utc::now().timestamp() - 9 * 60 * 60).to_string());
        if let Some(fork_config) = fork_config {
            anvil = anvil.fork(fork_config.url);
            if let Some(block_number) = fork_config.block_number {
                anvil = anvil.fork_block_number(block_number);
            }
        }
        if interactive {
            anvil = anvil.port(50101_u16);
        }
        anvil.try_spawn().map_err(|e| eyre!(e))
    })
    .await?
}
