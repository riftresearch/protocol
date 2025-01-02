// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

library Constants {
    uint16 public constant DEPOSIT_LOCKUP_PERIOD = 8 hours;
    uint64 public constant MIN_OUTPUT_SATS = 1000; // to prevent dust errors
    // TODO: Challenge period should scale with the number of blocks in the proof.
    // Set it to 2x the estimated proof generation time for n blocks.
    uint32 public constant MIN_DEPOSIT_AMOUNT = (10e3 / PROTOCOL_FEE_BP) + 1;
    uint8 public constant PROTOCOL_FEE_BP = 5; // maker + taker fee = 0.1%
    uint8 public constant MIN_CONFIRMATION_BLOCKS = 2;
    uint32 public constant SCALED_CHALLENGE_PERIOD_SLOPE = 354; // 3.54 seconds
    uint32 public constant SCALED_CHALLENGE_PERIOD_INTERCEPT = 21582; // 21.582 seconds
}
