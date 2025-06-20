// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

/// @dev τchallenge = 1.1 · (0.0418 · Δb + 57.5842) + fevm (seconds)
library ChallengePeriodLib {
    uint32 private constant SCALE = 1_000_000;      // 6-decimal fixed-point
    uint32 private constant A = 41_800;             // 0.0418 * 1e6
    uint32 private constant B = 57_584_200;         // 57.5842 * 1e6
    uint8  private constant BUFFER_PERCENTAGE = 10; // 10% safety buffer

    /// @notice Tp(Δb) with 6-decimal precision
    function _tp(uint64 deltaBlocks) private pure returns (uint64) {
        // Tp = A·Δb + B (scaled)
        return uint64(A) * deltaBlocks + B;
    }

    /// @param deltaBlocks Δb – blocks to remove from MMR
    /// @param blockFinalityTime chain finality time
    /// @return τchallenge (seconds, rounded up)
    function calculateChallengePeriod(
        uint64 deltaBlocks,
        uint64 blockFinalityTime
    ) internal pure returns (uint64) {
        uint64 tpScaled = _tp(deltaBlocks);
        uint64 withBuffer = tpScaled + (tpScaled * BUFFER_PERCENTAGE) / 100;
        uint64 totalScaled = withBuffer + blockFinalityTime * SCALE;
        
        // Convert to seconds, round up
        return (totalScaled + SCALE - 1) / SCALE;
    }
}