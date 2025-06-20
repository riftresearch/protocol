// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

import {FixedPointMathLib} from "solady/src/utils/FixedPointMathLib.sol";
import {ChallengePeriodLib} from "./ChallengePeriodLib.sol";

/// @dev t(k) = 142.59 + 53.92·√k + 10.32·k (minutes)
///      Tlock_up = 2·τchallenge(2016) + t(k) (seconds)
///      6-decimal fixed point arithmetic
library OrderLockupLib {
    using FixedPointMathLib for uint256;

    uint32 private constant SCALE = 1_000_000; // 6-dec fixed-point
    uint32 private constant BETA0 = 142_590_000; // 142.59 * 1e6
    uint32 private constant BETA1 =  53_920_000; // 53.92 * 1e6
    uint32 private constant BETA2 =  10_320_000; // 10.32 * 1e6

    error InvalidConfirmations();

    /// @notice Quantile wait time for k Bitcoin confirmations (seconds, rounded up)
    function t(uint8 k) internal pure returns (uint64) {
        if (k == 0) revert InvalidConfirmations();

        // rootScaled = √(k · 1e12) = √k · 1e6
        uint256 rootScaled = FixedPointMathLib.sqrt(uint256(k) * 1e12);

        // tScaled = β0 + β1·√k + β2·k (6-dec)
        uint256 tScaled =
              uint256(BETA0)
            + uint256(BETA1) * rootScaled / SCALE
            + uint256(BETA2) * uint256(k);

        // minutes rounded up → seconds
        return uint64((tScaled + SCALE - 1) / SCALE) * 60;
    }

    /// @notice Complete lock-up timer
    /// @param confirmations Required BTC confirmations
    /// @param blockFinalityTime chain finality time
    /// @return Tlock_up (seconds, rounded up)
    function calculateLockupPeriod(
        uint8  confirmations,
        uint64 blockFinalityTime
    ) internal pure returns (uint64) {
        uint64 challengePeriod = ChallengePeriodLib.calculateChallengePeriod(2016, blockFinalityTime);
        // Tlock_up = 2·τchallenge(2016) + t(k)
        return 2 * challengePeriod + t(confirmations);
    }
}
