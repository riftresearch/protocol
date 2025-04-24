// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;
import {Constants} from "./Constants.sol";

library RiftUtils {
    /// @notice Calculates protocol fee for a given deposit amount
    /// @param amount The amount being withdrawn from the user
    /// @return protocolFee The calculated protocol fee
    function calculateFeeFromDeposit(uint256 amount) internal pure returns (uint256 protocolFee) {
        protocolFee = (amount * uint256(Constants.TAKER_FEE_BP)) / 1e4; // bips scalar
    }

    /// @notice Calculates challenge period for a given amount of elapsed bitcoin blocks
    /// @param blocksElapsed The amount of elapsed bitcoin blocks
    /// @return challengePeriod The challenge period/delay, in seconds
    function calculateChallengePeriod(uint64 blocksElapsed) internal pure returns (uint256 challengePeriod) {
        challengePeriod =
            ((Constants.SCALED_PROOF_GEN_SLOPE * blocksElapsed + Constants.SCALED_PROOF_GEN_INTERCEPT) /
                Constants.PROOF_GEN_SCALING_FACTOR) +
            Constants.CHALLENGE_PERIOD_BUFFER;
    }

    /// @notice Calculates the deposit lockup period for a given number of confirmations
    /// @param confirmations The number of confirmations
    /// @return depositLockupPeriod The calculated deposit lockup period, in seconds
    function calculateDepositLockupPeriod(uint8 confirmations) internal pure returns (uint64 depositLockupPeriod) {
        depositLockupPeriod = Constants.DEPOSIT_LOCKUP_PERIOD_SCALAR * confirmations;
    }
}
