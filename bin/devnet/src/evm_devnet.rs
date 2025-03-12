use std::str::FromStr;
use std::sync::Arc;

use bitcoin_light_client_core::leaves::BlockLeaf;
use eyre::{eyre, Result};
use log::info;
use rift_sdk::{create_websocket_provider, WebsocketWalletProvider};
use tokio::time::Instant;

use alloy::{
    network::{Ethereum, EthereumWallet, TransactionBuilder},
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, U256},
    providers::{
        ext::AnvilApi,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, Provider, ProviderBuilder, RootProvider, WsConnect,
    },
    pubsub::PubSubFrontend,
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};

use crate::{
    // bring in the deployment logic/ABIs from lib
    deploy_contracts,
    MockTokenWebsocket,
    RiftExchangeWebsocket,
};

/// Holds all Ethereum-related devnet state.
pub struct EthDevnet {
    pub anvil: AnvilInstance,
    pub token_contract: Arc<MockTokenWebsocket>,
    pub rift_exchange_contract: Arc<RiftExchangeWebsocket>,
    pub funded_provider: Arc<WebsocketWalletProvider>,
    pub on_fork: bool,
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

        info!("Deploying RiftExchange & MockToken...");
        let t = Instant::now();
        let (rift_exchange, token_contract, deployment_block_number) = deploy_contracts(
            &anvil,
            circuit_verification_key_hash,
            genesis_mmr_root,
            tip_block_leaf,
            on_fork,
        )
        .await?;
        info!("Deployed in {:?}", t.elapsed());

        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let wallet = EthereumWallet::from(signer);

        let funded_provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_ws(WsConnect::new(anvil.ws_endpoint_url()))
            .await
            .expect("Failed connecting to anvil's WS");

        let devnet = EthDevnet {
            anvil,
            token_contract,
            rift_exchange_contract: rift_exchange,
            funded_provider: Arc::new(funded_provider),
            on_fork,
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
            let master_minter = self.token_contract.masterMinter().call().await?._0;

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
