use bitcoin::{
    consensus::{Decodable, Encodable},
    Amount, Transaction, Txid,
};
use bitcoincore_rpc_async::RpcApi;
use rift_sdk::{
    txn_builder::{self},
    MultichainAccount,
};
use sol_bindings::Order;

use super::fixtures::TestFixture;

/// Bitcoin transaction details needed for tests
pub struct BitcoinPaymentDetails {
    pub payment_tx: Transaction,
    pub payment_txid: Txid,
    pub funding_tx: Transaction,
    pub funding_txid: Txid,
}

/// Helper for creating Bitcoin payments in tests
pub struct BitcoinPaymentBuilder {
    funding_amount: u64,
    fee_sats: u64,
}

impl BitcoinPaymentBuilder {
    /// Create a new payment builder with default values
    pub fn new() -> Self {
        Self {
            funding_amount: 200_000_000, // 2 BTC to have plenty for fees
            fee_sats: 1000,
        }
    }
    
    pub fn with_funding_amount(mut self, amount: u64) -> Self {
        self.funding_amount = amount;
        self
    }
    
    pub fn with_fee(mut self, fee: u64) -> Self {
        self.fee_sats = fee;
        self
    }
    
    /// Fund a wallet and create payment transaction for an order
    pub async fn pay_for_order(
        self,
        fixture: &TestFixture,
        order: &Order,
        payer: &MultichainAccount,
    ) -> BitcoinPaymentDetails {
        self.pay_for_orders(fixture, &[order.clone()], payer).await
    }
    
    /// Fund a wallet and create payment transaction for multiple orders
    pub async fn pay_for_orders(
        self,
        fixture: &TestFixture,
        orders: &[Order],
        payer: &MultichainAccount,
    ) -> BitcoinPaymentDetails {
        // Fund the payer's Bitcoin wallet
        let funding_utxo = fixture
            .devnet
            .bitcoin
            .deal_bitcoin(
                payer.bitcoin_wallet.address.clone(),
                Amount::from_sat(self.funding_amount),
            )
            .await
            .unwrap();
        
        let wallet = &payer.bitcoin_wallet;
        
        // Parse the funding transaction
        let funding_tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&funding_utxo.hex).unwrap()).unwrap();
        
        // Find the output we can spend
        let txvout = funding_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| {
                output.script_pubkey.as_bytes() == wallet.get_p2wpkh_script().as_bytes()
                    && output.value == Amount::from_sat(self.funding_amount)
            })
            .map(|(index, _)| index as u32)
            .unwrap();
        
        // Get canonical txid
        let serialized = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&funding_tx);
        let mut reader = serialized.as_slice();
        let canon_bitcoin_tx = Transaction::consensus_decode_from_finite_reader(&mut reader).unwrap();
        let canon_txid = canon_bitcoin_tx.compute_txid();
        
        // Build payment transaction
        let payment_tx = txn_builder::build_rift_payment_transaction_single_input(
            orders,
            &canon_txid,
            &canon_bitcoin_tx,
            txvout,
            wallet,
            self.fee_sats,
        )
        .unwrap();
        
        let payment_txid = payment_tx.compute_txid();
        
        BitcoinPaymentDetails {
            payment_tx,
            payment_txid,
            funding_tx: canon_bitcoin_tx,
            funding_txid: canon_txid,
        }
    }
}

/// Broadcast a Bitcoin transaction and mine blocks for confirmations
pub async fn broadcast_and_mine(
    fixture: &TestFixture,
    payment: &BitcoinPaymentDetails,
    confirmation_blocks: u8,
) {
    let mut payment_tx_serialized = Vec::new();
    payment
        .payment_tx
        .consensus_encode(&mut payment_tx_serialized)
        .unwrap();
    
    // Broadcast the transaction
    fixture
        .devnet
        .bitcoin
        .rpc_client
        .send_raw_transaction(&payment_tx_serialized)
        .await
        .unwrap();
    
    println!("Bitcoin transaction broadcast: {}", payment.payment_txid);
    
    // Mine blocks for confirmations
    fixture
        .devnet
        .bitcoin
        .mine_blocks(confirmation_blocks as u64)
        .await
        .unwrap();
    
    println!("Mined {} blocks for confirmations", confirmation_blocks);
}

/// Quick helper to fund taker and pay for an order
pub async fn pay_for_order_as_taker(
    fixture: &TestFixture,
    order: &Order,
) -> BitcoinPaymentDetails {
    let payment = BitcoinPaymentBuilder::new()
        .pay_for_order(fixture, order, &fixture.accounts.taker)
        .await;
    
    broadcast_and_mine(fixture, &payment, order.confirmationBlocks).await;
    
    payment
}

/// Helper to get current Bitcoin block height
pub async fn get_bitcoin_block_height(fixture: &TestFixture) -> u64 {
    fixture
        .devnet
        .bitcoin
        .rpc_client
        .get_block_count()
        .await
        .unwrap()
}