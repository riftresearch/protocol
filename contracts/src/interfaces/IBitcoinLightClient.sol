// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

// --- Structs ---

/// @notice Represents a leaf node in the Bitcoin block header MMR.
struct BlockLeaf {
    bytes32 blockHash;
    uint32 height;
    uint256 cumulativeChainwork;
}

/// @notice Stores the tip block leaf associated with an MMR root.
struct BitcoinCheckpoint {
    bool established;
    BlockLeaf tipBlockLeaf;
}

/// @title IBitcoinLightClient
/// @notice Interface for the BitcoinLightClient contract.
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
    /// @param priorMmrRoot The MMR root before the update.
    /// @param newMmrRoot The new MMR root after the update.
    /// @param compressedBlockLeaves Compressed block leaf data included in the update proof.
    event BitcoinLightClientUpdated(bytes32 priorMmrRoot, bytes32 newMmrRoot, bytes compressedBlockLeaves);


    /// @notice Returns the current Merkle Mountain Range (MMR) root hash representing the tip of the verified Bitcoin chain.
    /// @return The current MMR root.
    function mmrRoot() external view returns (bytes32);

    /// @notice Retrieves checkpoint information for a given MMR root.
    /// @param mmrRootHash The MMR root to query.
    /// @return established Whether the checkpoint has been established.
    /// @return tipBlockLeaf The tip block leaf.
    function checkpoints(bytes32 mmrRootHash) external view returns (bool established, BlockLeaf memory tipBlockLeaf);


    /// @notice Returns the block height of the current tip of the verified chain.
    /// @return The height of the highest block verified by the light client.
    function getLightClientHeight() external view returns (uint32);
} 