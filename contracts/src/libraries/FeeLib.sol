// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

/**
 * @title FeeLib
 * @notice Library for calculating fees
 */
library FeeLib {
    /// @notice Calculates the minimum deposit amount for a given taker fee,
    /// @param takerFeeBips The taker fee in basis points
    /// @return minDepositAmount The minimum deposit amount
    /// @dev The minimum deposit amount is set such that the fees for an order will at least be 1 sat
    function calculateMinDepositAmount(uint16 takerFeeBips) internal pure returns (uint256 minDepositAmount) {
        if (takerFeeBips == 0) {
            minDepositAmount = 1;
        } else {
            minDepositAmount = (1e4 + takerFeeBips - 1) / takerFeeBips;
        }
    }

    /// @notice Calculates protocol fee for a given deposit amount
    /// @param amount The amount being withdrawing from the user
    /// @param takerFeeBips The taker fee in basis points
    /// @return protocolFee The calculated protocol fee
    function calculateFeeFromDeposit(uint256 amount, uint16 takerFeeBips) internal pure returns (uint256 protocolFee) {
        protocolFee = (amount * uint256(takerFeeBips)) / 1e4; // bips scalar
    }
}
