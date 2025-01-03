// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {Types} from "./Types.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

library LightClientVerificationLib {
    /**
     * @notice Verifies a block is included in the current MMR tree
     * @param blockLeaf The block leaf to verify inclusion for
     * @param inclusionProof The MMR proof for inclusion. Contains sibling hashes that are:
     *        - TODO: This has not been built, build merkle verifier in sys lang based on solady Merkle Proof
     *          Use the fact that MMRs have a specific direction based on where a leaf is in a tree, then
     *          build library in solidity using solady optimized merkle proof as base. Only deviation should be
     *          using mmr heights to specify sibling hash direction
     *        - Combined with the leaf until reaching a peak
     *        - Then combined with other peaks to form the bagged peaks
     *        - Finally combined with the leaf count to form the root
     * @return bool True if the block is included in the current tree
     */
    function proveBlockInclusion(
        Types.BlockLeaf memory blockLeaf,
        bytes32[] calldata inclusionProof,
        bytes32 mmrRoot
    ) internal pure returns (bool) {
        return true;
    }

    function proveBlockInclusionAtTip(
        Types.BlockLeaf memory blockLeaf,
        bytes32[] calldata inclusionProof,
        bytes32 mmrRoot
    ) internal pure returns (bool) {
        // last element in inclusionProof is the height of the mmr
        if (blockLeaf.height != uint32(uint256(inclusionProof[inclusionProof.length - 1]))) {
            return false;
        }
        return proveBlockInclusion(blockLeaf, inclusionProof, mmrRoot);
    }

    /**
     * @notice Builds a commitment leaf from a BlockLeaf struct
     * @param blockLeaf The block leaf to build a commitment for
     * @return bytes32 The commitment hash
     */
    function buildLeafCommitment(Types.BlockLeaf memory blockLeaf) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                blockLeaf.blockHash,
                bytes32(uint256(blockLeaf.height)),
                bytes32(blockLeaf.cumulativeChainwork)
            );
    }
}
