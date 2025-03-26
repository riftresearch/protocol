use alloy::hex;
use serde::{Deserialize, Serialize};
use sol_bindings::Types::{DepositVault, ProposedSwap};
use std::fmt;

// Custom Debug for the SwapStatus enum is optional, but let's keep it derived for simplicity.
// If you want a custom version, you can similarly define `impl fmt::Debug for SwapStatus { ... }`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SwapStatus {
    PaymentPending,
    ChallengePeriod,
    Completed,
    LiquidityWithdrawn,
}

impl fmt::Debug for SwapStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SwapStatus::PaymentPending => write!(f, "PaymentPending"),
            SwapStatus::ChallengePeriod => write!(f, "ChallengePeriod"),
            SwapStatus::Completed => write!(f, "Completed"),
            SwapStatus::LiquidityWithdrawn => write!(f, "LiquidityWithdrawn"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareDeposit {
    pub deposit: DepositVault,
    pub deposit_block_number: u64,
    pub deposit_block_hash: [u8; 32],
    pub deposit_txid: [u8; 32],
}

impl fmt::Debug for ChainAwareDeposit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwareDeposit")
            .field("deposit", &self.deposit)
            .field("deposit_block_number", &self.deposit_block_number)
            .field("deposit_block_hash", &hex::encode(self.deposit_block_hash))
            .field("deposit_txid", &hex::encode(self.deposit_txid))
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareRelease {
    pub release_txid: [u8; 32],
    pub release_block_hash: [u8; 32],
    pub release_block_number: u64,
}

impl fmt::Debug for ChainAwareRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwareRelease")
            .field("release_txid", &hex::encode(self.release_txid))
            .field("release_block_hash", &hex::encode(self.release_block_hash))
            .field("release_block_number", &self.release_block_number)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareWithdraw {
    pub withdraw_txid: [u8; 32],
    pub withdraw_block_hash: [u8; 32],
    pub withdraw_block_number: u64,
}

impl fmt::Debug for ChainAwareWithdraw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwareWithdraw")
            .field("withdraw_txid", &hex::encode(self.withdraw_txid))
            .field(
                "withdraw_block_hash",
                &hex::encode(self.withdraw_block_hash),
            )
            .field("withdraw_block_number", &self.withdraw_block_number)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainAwareProposedSwap {
    pub swap: ProposedSwap,
    pub swap_proof_txid: [u8; 32],
    pub swap_proof_block_hash: [u8; 32],
    pub swap_proof_block_number: u64,
    pub release: Option<ChainAwareRelease>,
}

impl fmt::Debug for ChainAwareProposedSwap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAwareProposedSwap")
            .field("swap", &self.swap)
            .field("swap_proof_txid", &hex::encode(self.swap_proof_txid))
            .field(
                "swap_proof_block_hash",
                &hex::encode(self.swap_proof_block_hash),
            )
            .field("swap_proof_block_number", &self.swap_proof_block_number)
            .field("release", &self.release)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OTCSwap {
    pub deposit: ChainAwareDeposit,
    pub swap_proofs: Vec<ChainAwareProposedSwap>,
    pub withdraw: Option<ChainAwareWithdraw>,
}

impl OTCSwap {
    pub fn swap_status(&self) -> SwapStatus {
        if self.withdraw.is_some() {
            SwapStatus::LiquidityWithdrawn
        } else if self.swap_proofs.is_empty() {
            SwapStatus::PaymentPending
        // If any swap proof has a release, it means the swap is complete
        } else if self.swap_proofs.iter().any(|swap| swap.release.is_none()) {
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
            .field("deposit", &self.deposit)
            .field("swap_proofs", &self.swap_proofs)
            .field("withdraw", &self.withdraw)
            .field("swap_status", &status)
            .finish()
    }
}
