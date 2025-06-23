use std::sync::Arc;

use bitcoin_light_client_core::leaves::BlockLeaf;
use eyre::{eyre, Result};
use log::info;
use rift_sdk::create_websocket_wallet_provider;
use sol_bindings::{
    Bundler3::Bundler3Instance, GeneralAdapter1::GeneralAdapter1Instance,
    ParaswapAdapter::ParaswapAdapterInstance, RiftAuctionAdaptor::RiftAuctionAdaptorInstance,
    RiftExchangeHarnessInstance,
};
use tokio::time::Instant;

use alloy::{
    eips::eip7251::ConsolidationRequest,
    network::TransactionBuilder,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, U256},
    providers::{ext::AnvilApi, DynProvider, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
};

use crate::{
    RiftExchangeHarnessWebsocket, SP1MockVerifier, TokenizedBTC, TokenizedBTCWebsocket,
    TAKER_FEE_BIPS, TOKEN_ADDRESS,
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
    ) -> Result<(Self, u64)> {
        let anvil = spawn_anvil(deploy_mode.clone()).await?;
        info!(
            "Anvil spawned at {}, chain_id={}",
            anvil.endpoint(),
            anvil.chain_id()
        );

        let private_key = anvil.keys()[0].clone().to_bytes().try_into().unwrap();

        let funded_provider = create_websocket_wallet_provider(
            anvil.ws_endpoint_url().to_string().as_str(),
            private_key,
        )
        .await?
        .erased();

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

        let devnet = EthDevnet {
            anvil,
            token_contract,
            rift_exchange_contract: rift_exchange,
            verifier_contract,
            funded_provider,
            deploy_mode,
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
    use alloy::{primitives::Address, providers::ext::AnvilApi, signers::local::PrivateKeySigner};

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
    bundler3_address: Address,
    rift_exchange_address: Address,
) -> Result<Arc<RiftAuctionAdaptorInstance<DynProvider>>> {
    let rift_auction_adaptor = RiftAuctionAdaptorInstance::deploy(
        funded_provider.clone(),
        bundler3_address,
        rift_exchange_address,
    )
    .await?;
    Ok(Arc::new(rift_auction_adaptor))
}

#[derive(Clone, Debug)]
pub struct ForkConfig {
    pub url: String,
    pub block_number: Option<u64>,
    pub bundler3_address: Address,
}

/// Spawns Anvil in a blocking task.
async fn spawn_anvil(mode: Mode) -> Result<AnvilInstance> {
    tokio::task::spawn_blocking(move || {
        let mut anvil = Anvil::new()
            .arg("--host")
            .arg("0.0.0.0")
            .block_time(1)
            .chain_id(1337)
            .arg("--steps-tracing")
            .arg("--timestamp")
            .arg((chrono::Utc::now().timestamp() - 9 * 60 * 60).to_string());
        match mode {
            Mode::Fork(fork_config) => {
                anvil = anvil.port(50101_u16);
                anvil = anvil.fork(fork_config.url);
                if let Some(block_number) = fork_config.block_number {
                    anvil = anvil.fork_block_number(block_number);
                }
            }
            Mode::Local => {}
        }
        anvil.try_spawn().map_err(|e| eyre!(e))
    })
    .await?
}
