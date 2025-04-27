// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {IBitcoinLightClient, BlockLeaf, BitcoinCheckpoint} from "./interfaces/IBitcoinLightClient.sol";

import {MMRProofLib} from "./libraries/MMRProof.sol";
import {HashLib} from "./libraries/HashLib.sol";

abstract contract BitcoinLightClient is IBitcoinLightClient {
    using HashLib for BlockLeaf;

    bytes32 public mmrRoot; 

    // Whenever the light client is updated, we store the new tip block leaf and the MMR root immutably here. The reason for this is
    // it guarantees that a light client update proof will always succeed at updating the light client to the new root assuming:
    // - The checkpoint the proof was built from was the real `mmrRoot` at some point in time
    // - The chainwork of the updated chain is greater than or equal to the chainwork of the current checkpoint
    // mmrRoot => checkpoint
    mapping(bytes32 => BitcoinCheckpoint) public checkpoints;

    /**
     * @notice Initializes the light client with an MMR root
     * @param _mmrRoot The initial MMR root
     * @param _tipBlockLeaf The tip block leaf of the initial MMR root
     * @dev The _mmrRoot and _tipBlockLeaf seed the initial state of the chain without explicit verification
     * The _mmrRoot's correctness is easily confirmed by building the complete block MMR offchain from genesis to _tipBlockLeaf
     */
    constructor(bytes32 _mmrRoot, BlockLeaf memory _tipBlockLeaf) {
        mmrRoot = _mmrRoot;
        checkpoints[_mmrRoot] = BitcoinCheckpoint({established: true, tipBlockLeaf: _tipBlockLeaf});
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
    function _updateRoot(
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        BlockLeaf memory tipBlockLeaf
    ) internal {
        // no need to do anything if the chain is already like the caller expected
        if (newMmrRoot == mmrRoot) {
            return;
        }

        // ensure the prior checkpoint is established
        BitcoinCheckpoint memory priorCheckpoint = checkpoints[priorMmrRoot];
        if (!priorCheckpoint.established) {
            revert CheckpointNotEstablished();
        }

        // ensure new chain has greater chainwork to the current checkpoint
        if (checkpoints[mmrRoot].tipBlockLeaf.cumulativeChainwork >= tipBlockLeaf.cumulativeChainwork) {
            revert ChainworkTooLow();
        }

        // add checkpoint and update mmrRoot
        checkpoints[newMmrRoot] = BitcoinCheckpoint({established: true, tipBlockLeaf: tipBlockLeaf});
        mmrRoot = newMmrRoot;
        emit BitcoinLightClientUpdated(priorMmrRoot, newMmrRoot);
    }

    function lightClientHeight() public view returns (uint32) {
        return checkpoints[mmrRoot].tipBlockLeaf.height;
    }

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
