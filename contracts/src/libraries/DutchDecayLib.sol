// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

import {FixedPointMathLib} from "solady/src/utils/FixedPointMathLib.sol";

/// @notice Helper functions for handling dutch decay
/// @author Modified from UniswapX (https://github.com/Uniswap/UniswapX/blob/v2.1.0/src/lib/DutchDecayLib.sol)
library DutchDecayLib {
    using FixedPointMathLib for uint256;


    /// @notice returns the linear interpolation between the two points
    /// @param startPoint The start of the decay
    /// @param endPoint The end of the decay
    /// @param currentPoint The current position in the decay
    /// @param startAmount The amount of the start of the decay
    /// @param endAmount The amount of the end of the decay
    function linearDecay(
        uint256 startPoint,
        uint256 endPoint,
        uint256 currentPoint,
        uint256 startAmount,
        uint256 endAmount
    ) internal pure returns (uint256) {
        return uint256(linearDecay(startPoint, endPoint, currentPoint, int256(startAmount), int256(endAmount)));
    }

    /// @notice returns the linear interpolation between the two points
    /// @param startPoint The start of the decay
    /// @param endPoint The end of the decay
    /// @param currentPoint The current position in the decay
    /// @param startAmount The amount of the start of the decay
    /// @param endAmount The amount of the end of the decay
    function linearDecay(
        uint256 startPoint,
        uint256 endPoint,
        uint256 currentPoint,
        int256 startAmount,
        int256 endAmount
    ) internal pure returns (int256) {
        if (currentPoint >= endPoint) {
            return endAmount;
        }
        uint256 elapsed = currentPoint - startPoint;
        uint256 duration = endPoint - startPoint;
        int256 delta;
        if (endAmount < startAmount) {
            delta = -int256(uint256(startAmount - endAmount).mulDiv(elapsed, duration));
        } else {
            delta = int256(uint256(endAmount - startAmount).mulDiv(elapsed, duration));
        }
        return startAmount + delta;
    }
}