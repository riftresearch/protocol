// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

// --- Structs ---

struct BlockLeaf {
    // The hash of the Bitcoin block
    bytes32 blockHash;
    // The height of the Bitcoin block
    uint32 height;
    // The cumulative chainwork of the Bitcoin block
    uint256 cumulativeChainwork;
}

struct BitcoinCheckpoint {
    // Whether the checkpoint has been established
    bool established;
    // The tip block leaf associated with the MMR root
    BlockLeaf tipBlockLeaf;
}

/**
 * @title The interface for the Bitcoin Light Client 
 * @notice A Bitcoin light client implementation that maintains a Merkle Mountain Range (MMR)
 * of Bitcoin blocks for verification purposes
 *
 * Each block is stored as a leaf in the MMR containing:
 * - Block hash
 * - Block height
 * - Cumulative chainwork
 * Updates to the MMR root rely on a ZK proof that the new leaves satisfy the Bitcoin Consensus rules.
 */
interface IBitcoinLightClient {

    // --- Errors ---

    /// @notice Thrown when a provided block is not found in the verified chain (MMR).
    error BlockNotInChain();
    /// @notice Thrown when a block does not have enough confirmations relative to the light client's current height.
    error BlockNotConfirmed();
    /// @notice Thrown when attempting to update the light client with a chain that has less cumulative work than the current one.
    error ChainworkTooLow();
    /// @notice Thrown when attempting to update from an MMR root that is not a known checkpoint.
    error CheckpointNotEstablished();

    // --- Events ---

    /// @notice Emitted when the light client's MMR root is successfully updated.
    /// @param priorMmrRoot The MMR root from which the update is built. 
    /// @param newMmrRoot The new MMR root after the update.
    event BitcoinLightClientUpdated(bytes32 priorMmrRoot, bytes32 newMmrRoot);


    /// @notice The MMR root the light client is currently attesting as the best chain.
    /// @return root The current MMR root.
    function mmrRoot() external view returns (bytes32 root);

    /// @notice Retrieves checkpoint information for a given MMR root.
    /// @param _mmrRoot The MMR root to query.
    /// @return established Whether the checkpoint has been established (ie. _mmrRoot was the light client mmrRoot at one point)
    /// @return tipBlockLeaf The tip block leaf associated with the root
    function checkpoints(bytes32 _mmrRoot) external view returns (bool established, BlockLeaf memory tipBlockLeaf);


    /// @notice Returns the block height of the current tip of the verified chain.
    /// @return height The height of the highest block verified by the light client.
    function lightClientHeight() external view returns (uint32 height);


    /// @notice Verifies that a block is included in the verified chain (MMR).
    /// @param blockLeaf The block leaf to verify.
    /// @param siblings The sibling nodes of the block leaf in the MMR.
    /// @param peaks The peak nodes of the block leaf in the MMR.
    function verifyBlockInclusion(
        BlockLeaf memory blockLeaf,
        bytes32[] memory siblings,
        bytes32[] memory peaks
    ) external view;
} 