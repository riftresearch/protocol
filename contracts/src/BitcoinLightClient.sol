// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {console} from "forge-std/src/console.sol";
import {Types} from "./libraries/Types.sol";
import {Events} from "./libraries/Events.sol";
import {Errors} from "./libraries/Errors.sol";

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
    bytes32 public mmrRoot; // The MMR root the light client is currently attesting as the best chain

    // Whenever the light client is updated, we store the new tip block leaf and the MMR root immutably here. The reason for this is
    // it guarantees that a light client update proof will always succeed at updating the light client to the new root assuming:
    // - The checkpoint the proof was built from was real at some point in time
    // - The chainwork of the updated chain is greater than or equal to the chainwork of the current checkpoint
    // mmrRoot => checkpoint
    mapping(bytes32 => Types.BitcoinCheckpoint) public checkpoints;

    /**
     * @notice Initializes the light client with an MMR root
     * @param _mmrRoot The initial MMR root
     * @dev The mmrRoot + _tipBlockLeaf are trusted state of the chain, ie being set with explicit verification
     * Because of this, it's critical that these are generated from some chunk of the chain that will not be reorged otherwise the light client
     * will be unable to fix itself TODO: is this true?
     */
    constructor(bytes32 _mmrRoot, Types.BlockLeaf memory tipBlockLeaf) {
        mmrRoot = _mmrRoot;
        checkpoints[_mmrRoot] = Types.BitcoinCheckpoint({established: true, tipBlockLeaf: tipBlockLeaf});
    }

    /**
     * @notice Extends the light client chain . The caller of this function must ensure:
     * - All committed blocks are in a sequential chain and satisfy PoW rules
     * - All blocks being committed to the MMR are provably available (stored in calldata/blobspace)
     * @param priorMmrRoot The mmr root the update was built from
     * @param newMmrRoot The updated mmr root
     * @dev Updates the root only if:
     *      1. The prior root matches a currently stored root
     *      2. The new root is different from the current root
     *      3. The chainwork of the updated chain is greater than or equal to the chainwork of the current checkpoint
     */
    // TODO: There is no need to pass the compressedBlockLeaves here, we can use trace_transaction to extract it from the calldata
    // so this is temporary simplicity
    function _updateRoot(
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        Types.BlockLeaf memory tipBlockLeaf,
        bytes calldata compressedBlockLeaves
    ) internal {
        // no need to do anything if the chain is already like the caller expected
        if (newMmrRoot == mmrRoot) {
            return;
        }

        // ensure the prior checkpoint is established
        Types.BitcoinCheckpoint memory priorCheckpoint = checkpoints[priorMmrRoot];
        if (!priorCheckpoint.established) {
            revert Errors.CheckpointNotEstablished();
        }

        // ensure new chain has greater chainwork to the current checkpoint
        if (checkpoints[mmrRoot].tipBlockLeaf.cumulativeChainwork >= tipBlockLeaf.cumulativeChainwork) {
            revert Errors.ChainworkTooLow();
        }

        // add checkpoint and update mmrRoot
        checkpoints[newMmrRoot] = Types.BitcoinCheckpoint({established: true, tipBlockLeaf: tipBlockLeaf});
        mmrRoot = newMmrRoot;
        emit Events.BitcoinLightClientUpdated(priorMmrRoot, newMmrRoot, compressedBlockLeaves);
    }

    function proveBlockInclusion(
        Types.BlockLeaf memory blockLeaf,
        bytes32[] calldata siblings,
        bytes32[] calldata peaks
    ) public view returns (bool) {
        return
            LightClientVerificationLib.proveBlockInclusion(
                blockLeaf,
                siblings,
                peaks,
                getLightClientHeight() + 1,
                mmrRoot
            );
    }

    function getLightClientHeight() public view returns (uint32) {
        return checkpoints[mmrRoot].tipBlockLeaf.height;
    }

    // validates that block hash exists in the MMR and that it's confirmation delta is sufficient relative to the current light client height
    function _ensureBitcoinInclusion(
        Types.BlockLeaf memory blockLeaf,
        bytes32[] calldata siblings,
        bytes32[] calldata peaks,
        uint32 expectedConfirmationBlocks
    ) internal view {
        if (!proveBlockInclusion(blockLeaf, siblings, peaks)) {
            revert Errors.InvalidSwapBlockInclusionProof();
        }
        if (getLightClientHeight() < blockLeaf.height + (expectedConfirmationBlocks - 1)) {
            revert Errors.NotEnoughConfirmations();
        }
    }
}
