use alloy::hex;
use serde::{Deserialize, Serialize};
use sol_bindings::{DutchAuction, Order, Payment};
use std::fmt;

// Custom Debug for the SwapStatus enum is optional, but let's keep it derived for simplicity.
// If you want a custom version, you can similarly define `impl fmt::Debug for SwapStatus { ... }`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SwapStatus {
    PaymentPending,
    ChallengePeriod,
    Completed,
    Refunded,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareOrder {
    pub order: Order,
    pub order_block_number: u64,
    pub order_block_hash: [u8; 32],
    pub order_txid: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FinalizedTransaction {
    pub txid: [u8; 32],
    pub block_hash: [u8; 32],
    pub block_number: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwarePayment {
    pub payment: Payment,
    pub creation: FinalizedTransaction,
    pub settlement: Option<FinalizedTransaction>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OTCSwap {
    pub order: ChainAwareOrder,
    pub payments: Vec<ChainAwarePayment>,
    pub refund: Option<FinalizedTransaction>,
}

impl OTCSwap {
    pub fn swap_status(&self) -> SwapStatus {
        if self.refund.is_some() {
            SwapStatus::Refunded
        } else if self.payments.is_empty() {
            SwapStatus::PaymentPending
        // If any swap proof has a release, it means the swap is complete
        } else if self
            .payments
            .iter()
            .any(|payment| payment.settlement.is_none())
        {
            SwapStatus::ChallengePeriod
        } else {
            SwapStatus::Completed
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareFill {
    pub order: ChainAwareOrder,
    pub creation: FinalizedTransaction,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareAuction {
    pub auction: DutchAuction,
    pub creation: FinalizedTransaction,
    pub filled: Option<ChainAwareFill>,
    pub refunded: Option<FinalizedTransaction>,
}

// Debug implementations
impl fmt::Debug for SwapStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SwapStatus::PaymentPending => write!(f, "PaymentPending"),
            SwapStatus::ChallengePeriod => write!(f, "ChallengePeriod"),
            SwapStatus::Completed => write!(f, "Completed"),
            SwapStatus::Refunded => write!(f, "Refunded"),
        }
    }
}

impl fmt::Debug for ChainAwareOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwareOrder")
            .field("order", &self.order)
            .field("order_block_number", &self.order_block_number)
            .field("order_block_hash", &hex::encode(self.order_block_hash))
            .field("order_txid", &hex::encode(self.order_txid))
            .finish()
    }
}

impl fmt::Debug for FinalizedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalizedTransaction")
            .field("txid", &hex::encode(self.txid))
            .field("block_hash", &hex::encode(self.block_hash))
            .field("block_number", &self.block_number)
            .finish()
    }
}

impl fmt::Debug for ChainAwarePayment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwarePayment")
            .field("payment", &self.payment)
            .field("creation", &self.creation)
            .field("settlement", &self.settlement)
            .finish()
    }
}

impl fmt::Debug for OTCSwap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = self.swap_status();
        f.debug_struct("OTCSwap")
            .field("order", &self.order)
            .field("payments", &self.payments)
            .field("refund", &self.refund)
            .field("swap_status", &status)
            .finish()
    }
}

impl fmt::Debug for ChainAwareFill {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwareFill")
            .field("order", &self.order)
            .field("creation", &self.creation)
            .finish()
    }
}

impl fmt::Debug for ChainAwareAuction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwareAuction")
            .field("auction", &self.auction)
            .field("creation", &self.creation)
            .field("filled", &self.filled)
            .field("refunded", &self.refunded)
            .finish()
    }
}
