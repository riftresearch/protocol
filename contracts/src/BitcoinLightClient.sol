// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

import {IBitcoinLightClient, BlockLeaf} from "./interfaces/IBitcoinLightClient.sol";

import {MMRProofLib} from "./libraries/MMRProof.sol";
import {HashLib} from "./libraries/HashLib.sol";

/**
 * @title Bitcoin Light Client
 * @notice A Bitcoin light client implementation that maintains a Merkle Mountain Range (MMR)
 * of Bitcoin blocks for verification purposes
 *
 * Each block is stored as a leaf in the MMR containing:
 * - Block hash
 * - Block height
 * - Cumulative chainwork
 * Updates to the MMR root rely on a proof that the new leaves satisfy the Bitcoin Consensus rules.
 */
abstract contract BitcoinLightClient is IBitcoinLightClient {
    using HashLib for BlockLeaf;

    bytes32 public mmrRoot;

    // Whenever the light client is updated, we store the new tip block leaf and the MMR root immutably here. The reason for this is
    // it guarantees that a light client update proof will always succeed at updating the light client to the new root assuming:
    // - The checkpoint the proof was built from was the real `mmrRoot` at some point in time
    // - The chainwork of the updated chain is greater than or equal to the chainwork of the current checkpoint
    // mmrRoot => tipBlockLeaf
    mapping(bytes32 => BlockLeaf) public checkpoints;

    /**
     * @notice Initializes the light client with an MMR root
     * @param _mmrRoot The initial MMR root
     * @param _tipBlockLeaf The tip block leaf of the initial MMR root
     * @dev The _mmrRoot and _tipBlockLeaf seed the initial state of the chain without explicit verification
     * The _mmrRoot's correctness is easily confirmed by building the complete block MMR offchain from genesis to _tipBlockLeaf
     */
    constructor(bytes32 _mmrRoot, BlockLeaf memory _tipBlockLeaf) {
        mmrRoot = _mmrRoot;
        checkpoints[_mmrRoot] = _tipBlockLeaf;
    }

    /**
     * @notice Extends the light client chain. The caller of this function must ensure:
     * - All committed blocks are in a sequential chain and satisfy PoW rules
     * - All blocks being committed to in the MMR are provably available (stored in calldata/blobspace)
     * @param priorMmrRoot The mmr root the update was built from
     * @param newMmrRoot The updated mmr root
     * @param tipBlockLeaf The tip of the chain at the `newMmrRoot`
     * @dev Updates the root if and only if:
     *      1. The prior root is an established checkpoint
     *      2. The new root is different from the current root
     *      3. The chainwork of the updated chain is greater than or equal to the chainwork of the current checkpoint
     */
    function _updateRoot(bytes32 priorMmrRoot, bytes32 newMmrRoot, BlockLeaf memory tipBlockLeaf) internal {
        // no need to do anything if the chain is already like the caller expected
        if (newMmrRoot == mmrRoot) {
            return;
        }

        // ensure the prior checkpoint is established
        if (checkpoints[priorMmrRoot].blockHash == bytes32(0)) {
            revert CheckpointNotEstablished();
        }

        // ensure new chain has greater chainwork to the current checkpoint
        if (checkpoints[mmrRoot].cumulativeChainwork >= tipBlockLeaf.cumulativeChainwork) {
            revert ChainworkTooLow();
        }

        // add checkpoint and update mmrRoot
        checkpoints[newMmrRoot] = tipBlockLeaf;
        mmrRoot = newMmrRoot;
        emit BitcoinLightClientUpdated(priorMmrRoot, newMmrRoot);
    }

    /// @inheritdoc IBitcoinLightClient
    function lightClientHeight() public view returns (uint32) {
        return checkpoints[mmrRoot].height;
    }

    /// @inheritdoc IBitcoinLightClient
    function verifyBlockInclusion(
        BlockLeaf memory blockLeaf,
        bytes32[] memory siblings,
        bytes32[] memory peaks
    ) public view {
        bytes32 leafHash = blockLeaf.hash();
        uint32 leafIndex = blockLeaf.height;
        if (!MMRProofLib.verifyProof(leafHash, leafIndex, siblings, peaks, lightClientHeight() + 1, mmrRoot)) {
            revert BlockNotInChain();
        }
    }

    /**
     * @notice Verifies that a block is included in the verified chain (MMR) and that it has the required number of confirmations
     * @param blockLeaf The block leaf to verify.
     * @param siblings The sibling nodes of the block leaf in the MMR.
     * @param peaks The peak nodes of the block leaf in the MMR.
     * @param expectedConfirmationBlocks The number of blocks that must be built on top of the blockLeaf
     */
    function _verifyBlockInclusionAndConfirmations(
        BlockLeaf memory blockLeaf,
        bytes32[] calldata siblings,
        bytes32[] calldata peaks,
        uint32 expectedConfirmationBlocks
    ) internal view {
        verifyBlockInclusion(blockLeaf, siblings, peaks);
        if (lightClientHeight() < blockLeaf.height + (expectedConfirmationBlocks - 1)) {
            revert BlockNotConfirmed();
        }
    }
}
