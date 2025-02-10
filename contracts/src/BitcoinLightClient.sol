// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {Types} from "./libraries/Types.sol";
import {Events} from "./libraries/Events.sol";

import {LightClientVerificationLib} from "./libraries/LightClientVerificationLib.sol";
import {MerkleProofLib} from "solady/src/utils/MerkleProofLib.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

/**
 * @title BitcoinLightClient
 * @notice A Bitcoin light client implementation that maintains a Merkle Mountain Range (MMR)
 * of Bitcoin block headers for verification purposes
 *
 * Each block is stored as a leaf of the MMR containing:
 * - Block hash
 * - Block height
 * - Cumulative chainwork
 * Updates to the MMR root rely on a ZK proof that the new leaves satisfy the Bitcoin Consensus rules.
 */
abstract contract BitcoinLightClient {
    bytes32 public mmrRoot;

    /**
     * @notice Initializes the light client with an MMR root
     * @param _mmrRoot The initial MMR root
     */
    constructor(bytes32 _mmrRoot) {
        mmrRoot = _mmrRoot;
    }

    /**
     * @notice Updates the MMR root. The caller must ensure:
     * - The new root is built from a previously known header and all new headers satisfy PoW rules
     * - All leaves being committed to the MMR are provably available (stored in calldata/blobspace)
     * @param priorMmrRoot The expected current MMR root
     * @param newMmrRoot The new MMR root to update to
     * @dev Updates the root only if:
     *      1. The prior root matches the current stored root
     *      2. The prior root is different from the new root
     */
    function _updateRoot(bytes32 priorMmrRoot, bytes32 newMmrRoot, bytes calldata compressedBlockLeaves) internal {
        if (priorMmrRoot != mmrRoot || priorMmrRoot == newMmrRoot) return;
        mmrRoot = newMmrRoot;
        emit Events.BlockTreeUpdated(newMmrRoot, compressedBlockLeaves);
    }

    function _proveBlockInclusion(
        Types.BlockLeaf memory blockLeaf,
        bytes32[] calldata siblings,
        bytes32[] calldata peaks,
        uint32 tipBlockHeight
    ) public view returns (bool) {
        return LightClientVerificationLib.proveBlockInclusion(blockLeaf, siblings, peaks, tipBlockHeight + 1, mmrRoot);
    }

    function _proveBlockInclusionAtTip(
        Types.BlockLeaf memory blockLeaf,
        bytes32[] calldata siblings,
        bytes32[] calldata peaks
    ) public view returns (bool) {
        return
            LightClientVerificationLib.proveBlockInclusion(blockLeaf, siblings, peaks, blockLeaf.height + 1, mmrRoot);
    }
}
