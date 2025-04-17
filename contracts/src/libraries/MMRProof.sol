// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

library MMRProofLib {
    /**
     * @notice Verifies a block is included in the current MMR tree.
     * @param leafHash The hash of the block leaf to verify inclusion for.
     * @param leafIndex The index of the block leaf to verify inclusion for.
     * @param siblings The sibling hashes for the block from leaf up to a peak.
     * @param peaks The peaks array in the MMR (one of which should match the final folded leaf).
     * @param leafCount The "leaf count" or total number of leaves in the MMR (tip block height + 1).
     * @param mmrRoot The root of the MMR computed by hashing (tip block height, bagged_peaks).
     * @return bool True if the block is included in the current MMR tree.
     * @dev **WARNING:** The `leafHash` parameter MUST be computed. Do NOT pass a `leafHash` directly from calldata.
     */
    function verifyProof(
        bytes32 leafHash,
        uint256 leafIndex,
        bytes32[] calldata siblings,
        bytes32[] calldata peaks,
        uint32 leafCount,
        bytes32 mmrRoot
    ) internal pure returns (bool) {
        // 1. Fold the leaf up to a peak, using the leafIndex to know left vs right.
        for (uint256 i = 0; i < siblings.length; i++) {
            bool isRight = (leafIndex & 1) == 1;
            leafIndex >>= 1;
            if (isRight) {
                // If the old index was odd, the sibling is on the left
                leafHash = EfficientHashLib.hash(siblings[i], leafHash);
            } else {
                // If the old index was even, the sibling is on the right
                leafHash = EfficientHashLib.hash(leafHash, siblings[i]);
            }
        }

        // 3. Ensure this folded hash is one of the peaks
        bool foundPeak = false;
        for (uint256 i = 0; i < peaks.length; i++) {
            if (peaks[i] == leafHash) {
                foundPeak = true;
                break;
            }
        }

        if (!foundPeak) {
            return false;
        }

        // 4. "Bag" the peaks into one
        bytes32 baggedPeaks = bagPeaks(peaks);

        if (baggedPeaks == bytes32(0)) {
            return false; // no valid peaks
        }

        // 5. Hash (tipBlockHeight, baggedPeaks) to compute the final MMR root
        bytes32 computedRoot = EfficientHashLib.hash(bytes32(uint256(leafCount)), baggedPeaks);

        // 6. Compare with the provided root
        return (computedRoot == mmrRoot);
    }

    /**
     * @notice "Bags" (folds) peaks in right-to-left order:
     *  Rust `bag_peaks` does `fold(None, |acc, peak| match acc { None => peak, Some(prev) => hash(peak, prev) })`
     */
    function bagPeaks(bytes32[] calldata peaks) internal pure returns (bytes32) {
        if (peaks.length == 0) {
            return bytes32(0);
        }

        // Start from the right-most peak
        bytes32 acc = peaks[peaks.length - 1];

        // Fold peaks in reverse (right -> left)
        for (uint256 i = peaks.length - 1; i > 0; ) {
            unchecked {
                i--;
            }
            acc = EfficientHashLib.hash(peaks[i], acc);
        }

        return acc;
    }
}
