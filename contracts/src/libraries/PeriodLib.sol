// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

library PeriodLib {
    // TODO: What is the security parameter for 2 hours per confirmation?
    uint32 public constant DEPOSIT_LOCKUP_PERIOD_SCALAR = 2 hours; // 2 hours per confirmation block
    uint32 public constant CHALLENGE_PERIOD_BUFFER = 5 minutes; //TODO: change when we have a better estimate of e2e block trigger -> proof gen -> publish proof latency
    uint32 public constant SCALED_PROOF_GEN_SLOPE = 133;
    uint32 public constant SCALED_PROOF_GEN_INTERCEPT = 58291;
    uint32 public constant PROOF_GEN_SCALING_FACTOR = 1000;

    /// @notice Calculates challenge period for a given amount of elapsed bitcoin blocks
    /// @param blocksElapsed The amount of elapsed bitcoin blocks
    /// @return challengePeriod The challenge period/delay, in seconds
    function calculateChallengePeriod(uint64 blocksElapsed) internal pure returns (uint256 challengePeriod) {
        challengePeriod =
            ((SCALED_PROOF_GEN_SLOPE * blocksElapsed + SCALED_PROOF_GEN_INTERCEPT) / PROOF_GEN_SCALING_FACTOR) +
            CHALLENGE_PERIOD_BUFFER;
    }

    /// @notice Calculates the deposit lockup period for a given number of confirmations
    /// @param confirmations The number of confirmations
    /// @return depositLockupPeriod The calculated deposit lockup period, in seconds
    function calculateDepositLockupPeriod(uint8 confirmations) internal pure returns (uint64 depositLockupPeriod) {
        depositLockupPeriod = DEPOSIT_LOCKUP_PERIOD_SCALAR * confirmations;
    }
}
