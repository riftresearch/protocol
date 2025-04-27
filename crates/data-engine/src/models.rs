use alloy::hex;
use serde::{Deserialize, Serialize};
use sol_bindings::{Order, Payment};
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

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareOrder {
    pub order: Order,
    pub order_block_number: u64,
    pub order_block_hash: [u8; 32],
    pub order_txid: [u8; 32],
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

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareSettlement {
    pub settlement_txid: [u8; 32],
    pub settlement_block_hash: [u8; 32],
    pub settlement_block_number: u64,
}

impl fmt::Debug for ChainAwareSettlement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwareSettlement")
            .field("settlement_txid", &hex::encode(self.settlement_txid))
            .field(
                "settlement_block_hash",
                &hex::encode(self.settlement_block_hash),
            )
            .field("settlement_block_number", &self.settlement_block_number)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareRefund {
    pub refund_txid: [u8; 32],
    pub refund_block_hash: [u8; 32],
    pub refund_block_number: u64,
}

impl fmt::Debug for ChainAwareRefund {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwareRefund")
            .field("refund_txid", &hex::encode(self.refund_txid))
            .field("refund_block_hash", &hex::encode(self.refund_block_hash))
            .field("refund_block_number", &self.refund_block_number)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwarePayment {
    pub payment: Payment,
    pub payment_txid: [u8; 32],
    pub payment_block_hash: [u8; 32],
    pub payment_block_number: u64,
    pub settlement: Option<ChainAwareSettlement>,
}

impl fmt::Debug for ChainAwarePayment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwarePayment")
            .field("payment", &self.payment)
            .field("payment_txid", &hex::encode(self.payment_txid))
            .field("payment_block_hash", &hex::encode(self.payment_block_hash))
            .field("payment_block_number", &self.payment_block_number)
            .field("settlement", &self.settlement)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OTCSwap {
    pub order: ChainAwareOrder,
    pub payments: Vec<ChainAwarePayment>,
    pub refund: Option<ChainAwareRefund>,
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
