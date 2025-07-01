use alloy::{
    primitives::{utils::format_units, Address, U256},
    providers::Provider,
    sol_types::SolEvent,
};
use sol_bindings::{BaseCreateOrderParams, CreateOrderParams, Order, OrderCreated};

use super::fixtures::TestFixture;

/// Helper for creating orders in tests
pub struct OrderBuilder {
    deposit_amount: U256,
    expected_sats: u64,
    confirmation_blocks: u8,
    designated_receiver: Address,
    salt: [u8; 32],
}

impl OrderBuilder {
    /// Create a new order builder with default values
    pub fn new() -> Self {
        Self {
            deposit_amount: U256::from(100_000_000u128), // 1 wrapped bitcoin
            expected_sats: 100_000_000u64,              // 1 bitcoin
            confirmation_blocks: 2,
            designated_receiver: Address::ZERO,
            salt: [0x44; 32],
        }
    }
    
    pub fn with_deposit_amount(mut self, amount: U256) -> Self {
        self.deposit_amount = amount;
        self
    }
    
    pub fn with_expected_sats(mut self, sats: u64) -> Self {
        self.expected_sats = sats;
        self
    }
    
    pub fn with_confirmation_blocks(mut self, blocks: u8) -> Self {
        self.confirmation_blocks = blocks;
        self
    }
    
    pub fn with_designated_receiver(mut self, receiver: Address) -> Self {
        self.designated_receiver = receiver;
        self
    }
    
    pub fn with_salt(mut self, salt: [u8; 32]) -> Self {
        self.salt = salt;
        self
    }
    
    /// Create an order using the specified maker
    pub async fn create_as_maker(
        self,
        fixture: &TestFixture,
        maker_index: usize,
    ) -> Order {
        let maker_account = if maker_index == 0 {
            &fixture.accounts.maker
        } else {
            &fixture.accounts.additional_makers[maker_index - 1]
        };
        
        let provider = fixture.create_provider_for(maker_account).await;
        let rift_exchange = fixture.devnet.ethereum.rift_exchange_contract.clone();
        let token_contract = fixture.devnet.ethereum.token_contract.clone();
        
        // Approve tokens
        let decimals = token_contract.decimals().call().await.unwrap();
        println!(
            "Approving {} tokens for maker",
            format_units(self.deposit_amount, decimals).unwrap()
        );
        
        let approve_call = token_contract.approve(*rift_exchange.address(), self.deposit_amount);
        
        provider
            .send_transaction(approve_call.into_transaction_request())
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();
        
        // Get MMR proof data
        let (safe_leaf, safe_siblings, safe_peaks) = fixture
            .devnet
            .rift_indexer
            .get_tip_proof()
            .await
            .unwrap();
        
        let safe_leaf: sol_bindings::BlockLeaf = safe_leaf.into();
        
        // Create order parameters
        let bitcoin_script_pubkey = maker_account.bitcoin_wallet.get_p2wpkh_script().to_bytes();
        
        let deposit_params = CreateOrderParams {
            base: BaseCreateOrderParams {
                owner: maker_account.ethereum_address,
                bitcoinScriptPubKey: bitcoin_script_pubkey.into(),
                salt: self.salt.into(),
                confirmationBlocks: self.confirmation_blocks,
                safeBlockLeaf: safe_leaf,
            },
            expectedSats: self.expected_sats,
            depositAmount: self.deposit_amount,
            designatedReceiver: if self.designated_receiver == Address::ZERO {
                fixture.accounts.taker.ethereum_address
            } else {
                self.designated_receiver
            },
            safeBlockSiblings: safe_siblings.iter().map(From::from).collect(),
            safeBlockPeaks: safe_peaks.iter().map(From::from).collect(),
        };
        
        // Create the order
        let deposit_call = rift_exchange.createOrder(deposit_params);
        let receipt = provider
            .send_transaction(deposit_call.into_transaction_request())
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();
        
        // Extract order from logs
        let receipt_logs = receipt.inner.logs();
        let order_created_log = OrderCreated::decode_log(
            &receipt_logs
                .iter()
                .find(|log| *log.topic0().unwrap() == OrderCreated::SIGNATURE_HASH)
                .unwrap()
                .inner,
        )
        .unwrap();
        
        let order = order_created_log.data.order.clone();
        println!("Created order with index: {}", order.index);
        
        order
    }
    
    /// Create an order using the default maker account
    pub async fn create(self, fixture: &TestFixture) -> Order {
        self.create_as_maker(fixture, 0).await
    }
}

/// Quick helper to create an order with default settings
pub async fn create_default_order(fixture: &TestFixture) -> Order {
    OrderBuilder::new().create(fixture).await
}

/// Create multiple orders with different makers
pub async fn create_orders_with_different_makers(
    fixture: &TestFixture,
    count: usize,
) -> Vec<Order> {
    let mut orders = Vec::new();
    
    for i in 0..count {
        let order = OrderBuilder::new()
            .with_salt([i as u8; 32])
            .create_as_maker(fixture, i)
            .await;
        orders.push(order);
    }
    
    orders
}