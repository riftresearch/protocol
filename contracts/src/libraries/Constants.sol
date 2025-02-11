// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

library Constants {
    // TODO: What is the security parameter for 2 hours per confirmation?
    uint32 public constant DEPOSIT_LOCKUP_PERIOD_SCALAR = 2 hours; // 2 hours per confirmation block
    uint16 public constant MIN_OUTPUT_SATS = 1000; // to prevent dust errors
    uint32 public constant MIN_DEPOSIT_AMOUNT = (10e3 / PROTOCOL_FEE_BP) + 1;
    uint8 public constant PROTOCOL_FEE_BP = 5; // maker + taker fee = 0.1%
    uint8 public constant MIN_CONFIRMATION_BLOCKS = 2;
    uint32 public constant CHALLENGE_PERIOD_BUFFER = 5 minutes; //TODO: change when we have a better estimate of e2e block trigger -> proof gen -> publish proof latency
    uint32 public constant SCALED_PROOF_GEN_SLOPE = 133;
    uint32 public constant SCALED_PROOF_GEN_INTERCEPT = 58291;
    uint32 public constant PROOF_GEN_SCALING_FACTOR = 1000;
}
