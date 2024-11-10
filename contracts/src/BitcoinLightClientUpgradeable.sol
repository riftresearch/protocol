// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {Initializable} from "@openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

error InvalidLeavesCommitment();

/**
 * @title BitcoinLightClientUpgradeable
 * @notice A Bitcoin client implementation that maintains a Merkle Mountain Range (MMR)
 * of Bitcoin block headers for verification purposes
 * @dev This contract is designed to be used with the OpenZeppelin upgradeable contracts pattern
 *
 * Each block is stored as a leaf of thhe MMR containing:
 * - Block hash
 * - Block height
 * - Cumulative chainwork
 * Updates to the MMR root rely on a ZK proof that the new leaves satisfy the Bitcoin Consensus rules.
 */
contract BitcoinLightClientUpgradeable is Initializable {
    bytes32 public mmrRoot;
    BlockLeaf public initialCheckpointLeaf;

    struct BlockLeaf {
        bytes32 blockHash;
        uint64 height;
        uint256 cumulativeChainwork;
    }

    event BlockTreeUpdated(bytes32 treeRoot);

    /** @custom:oz-upgrades-unsafe-allow constructor */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the light client with an MMR root and initial checkpoint
     * @param _mmrRoot The initial MMR root
     * @param _initialCheckpointLeaf The initial checkpoint block leaf
     */
    function __BitcoinLightClientUpgradeable_init(
        bytes32 _mmrRoot,
        BlockLeaf calldata _initialCheckpointLeaf
    ) internal onlyInitializing {
        mmrRoot = _mmrRoot;
        initialCheckpointLeaf = _initialCheckpointLeaf;
    }

    /**
     * @notice Updates the MMR root with verification of new leaves data availability
     * @param priorMmrRoot The expected current MMR root
     * @param newMmrRoot The new MMR root to update to
     * @dev Updates the root only if:
     *      1. The prior root matches the current stored root
     *      2. The prior root is different from the new root
     */
    function updateRoot(bytes32 priorMmrRoot, bytes32 newMmrRoot) internal {
        if (priorMmrRoot != mmrRoot || priorMmrRoot == newMmrRoot) return;

        mmrRoot = newMmrRoot;
        emit BlockTreeUpdated(newMmrRoot);
    }

    /**
     * @notice Verifies a block is included in the current MMR tree
     * @param inclusionProof The merkle proof for inclusion
     * @return bool True if the block is included in the current tree
     */
    function proveBlockInclusion(
        BlockLeaf memory blockLeaf,
        bytes32[] calldata inclusionProof
    ) public view returns (bool) {
        return MerkleProofLib.verify(inclusionProof, mmrRoot, buildLeafCommitment(blockLeaf));
    }

    /**
     * @notice Builds a commitment leaf from a BlockLeaf struct
     * @param blockLeaf The block leaf to build a commitment for
     * @return bytes32 The commitment hash
     */
    function buildLeafCommitment(BlockLeaf memory blockLeaf) public pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                blockLeaf.blockHash,
                bytes32(uint256(blockLeaf.height)),
                bytes32(blockLeaf.cumulativeChainwork)
            );
    }
}
