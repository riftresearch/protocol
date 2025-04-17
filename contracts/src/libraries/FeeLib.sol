// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

library FeeLib {
    function calculateMinDepositAmount(uint16 takerFeeBips) internal pure returns (uint256 minDepositAmount) {
        minDepositAmount = (1e4 + takerFeeBips - 1) / takerFeeBips;
    }

    /// @notice Calculates protocol fee for a given deposit amount
    /// @param amount The amount being withdrawing from the user
    /// @param takerFeeBips The taker fee in basis points
    /// @return protocolFee The calculated protocol fee
    function calculateFeeFromDeposit(uint256 amount, uint16 takerFeeBips) internal pure returns (uint256 protocolFee) {
        protocolFee = (amount * uint256(takerFeeBips)) / 1e4; // bips scalar
    }
}
