// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

library Constants {
    // TODO: What is the security parameter for 2 hours per confirmation?
    uint32 public constant DEPOSIT_LOCKUP_PERIOD_SCALAR = 2 hours; // 2 hours per confirmation block
    uint8 public constant TAKER_FEE_BP = 5; // 0.05%
    uint16 public constant MIN_OUTPUT_SATS = 1000; // to prevent dust errors on btc side
    uint16 public constant MIN_DEPOSIT_SATS = (1e4 + TAKER_FEE_BP - 1) / TAKER_FEE_BP; // the min deposit amount such that the fee is at least 1 sat
    uint8 public constant MIN_CONFIRMATION_BLOCKS = 2;
    uint32 public constant CHALLENGE_PERIOD_BUFFER = 5 minutes; //TODO: change when we have a better estimate of e2e block trigger -> proof gen -> publish proof latency
    uint32 public constant SCALED_PROOF_GEN_SLOPE = 133;
    uint32 public constant SCALED_PROOF_GEN_INTERCEPT = 58291;
    uint32 public constant PROOF_GEN_SCALING_FACTOR = 1000;
}
