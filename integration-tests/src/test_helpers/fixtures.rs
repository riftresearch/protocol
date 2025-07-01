use alloy::primitives::U256;
use alloy::providers::ext::AnvilApi;
use devnet::RiftDevnet;
use rift_sdk::{create_websocket_wallet_provider, MultichainAccount};
use std::sync::Arc;

/// Common test fixture containing all necessary components for integration tests
pub struct TestFixture {
    pub devnet: Arc<RiftDevnet>,
    pub accounts: TestAccounts,
}

/// Test accounts with both Bitcoin and Ethereum wallets
pub struct TestAccounts {
    pub maker: MultichainAccount,
    pub taker: MultichainAccount,
    pub hypernode_operator: MultichainAccount,
    pub additional_makers: Vec<MultichainAccount>,
}

impl TestFixture {
    /// Create a new test fixture with standard setup
    pub async fn new() -> Self {
        Self::with_config(TestConfig::default()).await
    }

    /// Create a test fixture with custom configuration
    pub async fn with_config(config: TestConfig) -> Self {
        let accounts = TestAccounts::new(config.num_additional_makers);
        
        // Build devnet with funded addresses
        let mut devnet_builder = RiftDevnet::builder()
            .funded_evm_address(accounts.maker.ethereum_address.to_string())
            .funded_evm_address(accounts.taker.ethereum_address.to_string())
            .funded_evm_address(accounts.hypernode_operator.ethereum_address.to_string());
        
        for maker in &accounts.additional_makers {
            devnet_builder = devnet_builder.funded_evm_address(maker.ethereum_address.to_string());
        }
        
        let (devnet, _) = devnet_builder.build().await.expect("Failed to build devnet");
        
        // Enable automatic mining if configured
        if config.auto_mine_ethereum {
            devnet
                .ethereum
                .funded_provider
                .anvil_set_interval_mining(1)
                .await
                .unwrap();
        }
        
        // Fund hypernode operator with max ETH
        devnet
            .ethereum
            .fund_eth_address(accounts.hypernode_operator.ethereum_address, U256::MAX)
            .await
            .unwrap();
        
        TestFixture {
            devnet: Arc::new(devnet),
            accounts,
        }
    }
    
    /// Get the checkpoint file path
    pub fn checkpoint_file_path(&self) -> String {
        self.devnet
            .checkpoint_file_handle
            .path()
            .to_string_lossy()
            .to_string()
    }
    
    /// Create a wallet provider for a given account
    pub async fn create_provider_for(&self, account: &MultichainAccount) -> impl alloy::providers::Provider {
        create_websocket_wallet_provider(
            self.devnet.ethereum.anvil.ws_endpoint_url().to_string().as_str(),
            account.secret_bytes,
        )
        .await
        .expect("Failed to create provider")
    }
}

impl TestAccounts {
    pub fn new(num_additional_makers: usize) -> Self {
        let mut additional_makers = Vec::new();
        for i in 0..num_additional_makers {
            additional_makers.push(MultichainAccount::new((3 + i) as u32));
        }
        
        Self {
            maker: MultichainAccount::new(1),
            taker: MultichainAccount::new(2),
            hypernode_operator: MultichainAccount::new(3),
            additional_makers,
        }
    }
}

/// Configuration options for test fixtures
pub struct TestConfig {
    pub auto_mine_ethereum: bool,
    pub num_additional_makers: usize,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            auto_mine_ethereum: true,
            num_additional_makers: 0,
        }
    }
}