// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {Types} from "./libraries/Types.sol";
import {Events} from "./libraries/Events.sol";

import {LightClientVerificationLib} from "./libraries/LightClientVerificationLib.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

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
    Types.BlockLeaf public initialCheckpointLeaf;

    /**
     * @notice Initializes the light client with an MMR root and initial checkpoint
     * @param _mmrRoot The initial MMR root
     * @param _initialCheckpointLeaf The initial checkpoint block leaf
     */
    constructor(bytes32 _mmrRoot, Types.BlockLeaf memory _initialCheckpointLeaf) {
        mmrRoot = _mmrRoot;
        initialCheckpointLeaf = _initialCheckpointLeaf;
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
    function _updateRoot(bytes32 priorMmrRoot, bytes32 newMmrRoot) internal {
        if (priorMmrRoot != mmrRoot || priorMmrRoot == newMmrRoot) return;
        mmrRoot = newMmrRoot;
        emit Events.BlockTreeUpdated(newMmrRoot);
    }

    function _proveBlockInclusion(
        Types.BlockLeaf memory blockLeaf,
        bytes32[] calldata inclusionProof
    ) public view returns (bool) {
        return LightClientVerificationLib.proveBlockInclusion(blockLeaf, inclusionProof, mmrRoot);
    }

    function _proveBlockInclusionAtTip(
        Types.BlockLeaf memory blockLeaf,
        bytes32[] calldata inclusionProof
    ) public view returns (bool) {
        return LightClientVerificationLib.proveBlockInclusionAtTip(blockLeaf, inclusionProof, mmrRoot);
    }
}
