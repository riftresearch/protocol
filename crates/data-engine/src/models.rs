use serde::{Deserialize, Serialize};
use sol_bindings::Types::{DepositVault, ProposedSwap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapStatus {
    PaymentPending,
    ChallengePeriod,
    Completed,
    LiquidityWithdrawn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAwareDeposit {
    pub deposit: DepositVault,
    pub deposit_block_number: u64,
    pub deposit_block_hash: [u8; 32],
    pub deposit_txid: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAwareProposedSwap {
    pub swap: ProposedSwap,
    pub swap_proof_txid: [u8; 32],
    pub swap_proof_block_hash: [u8; 32],
    pub swap_proof_block_number: u64,
    pub release: Option<ChainAwareRelease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAwareWithdraw {
    pub withdraw_txid: [u8; 32],
    pub withdraw_block_hash: [u8; 32],
    pub withdraw_block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAwareRelease {
    pub release_txid: [u8; 32],
    pub release_block_hash: [u8; 32],
    pub release_block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        } else if self.swap_proofs.iter().any(|swap| swap.release.is_some()) {
            SwapStatus::ChallengePeriod
        } else {
            SwapStatus::Completed
        }
    }
}
