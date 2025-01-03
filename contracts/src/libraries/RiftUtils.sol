// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;
import {Constants} from "./Constants.sol";

library RiftUtils {
    /// @notice Calculates protocol fee for a given deposit amount
    /// @param amount The amount being deposited/swapped
    /// @return protocolFee The calculated protocol fee, either 0.1% or MIN_PROTOCOL_FEE, whichever is larger
    function calculateFeeFromInitialDeposit(uint256 amount) internal pure returns (uint256 protocolFee) {
        protocolFee = (amount * Constants.PROTOCOL_FEE_BP) / 10e3; // bpScale value
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
}
