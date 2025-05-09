// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

struct BlockLeaf {
    // The hash of the Bitcoin block
    bytes32 blockHash;
    // The height of the Bitcoin block
    uint32 height;
    // The cumulative chainwork of the Bitcoin block
    uint256 cumulativeChainwork;
}

struct Checkpoint {
    // The height of the tip Bitcoin block
    uint32 height;
    // The cumulative chainwork of the tip Bitcoin block
    uint256 cumulativeChainwork;
}

/**
 * @title Interface for the Bitcoin Light Client contract
 */
interface IBitcoinLightClient {
    error BlockNotInChain();
    error BlockNotConfirmed();
    error ChainworkTooLow();
    error CheckpointNotEstablished();

    event BitcoinLightClientUpdated(bytes32 priorMmrRoot, bytes32 newMmrRoot);

    /// @notice The MMR root that includes all the blocks the light client is currently attesting as the best chain.
    /// @return root The current MMR root.
    function mmrRoot() external view returns (bytes32 root);

    /// @notice Retrieves checkpoint information for a given MMR root.
    /// @param _mmrRoot The MMR root to query.
    /// @return height The height of the tip Bitcoin block
    /// @return cumulativeChainwork The cumulative chainwork of the tip Bitcoin block
    function checkpoints(bytes32 _mmrRoot) external view returns (uint32 height, uint256 cumulativeChainwork);

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
