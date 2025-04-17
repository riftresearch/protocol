// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/src/Test.sol";
import {RiftTest} from "../utils/RiftTest.sol";

import {Types} from "../../src/libraries/Types.sol";
import {MMRProofLib} from "../../src/libraries/MMRProof.sol";
import {HashLib} from "../../src/libraries/HashLib.sol";

/**
 * @notice Harness contract that exposes MMRProofLib as external functions
 *         so we can call them via normal external calls in our tests.
 */
contract MMRProofLibHarness {
    function verifyProof(
        bytes32 blockLeafHash,
        uint32 leafIndex,
        bytes32[] calldata siblings,
        bytes32[] calldata peaks,
        uint32 leafCount,
        bytes32 mmrRoot
    ) external pure returns (bool) {
        return MMRProofLib.verifyProof(blockLeafHash, leafIndex, siblings, peaks, leafCount, mmrRoot);
    }
}

contract MMRProofLibUnitTest is RiftTest {
    using HashLib for Types.BlockLeaf;
    MMRProofLibHarness internal harness;

    function setUp() public override {
        super.setUp();
        harness = new MMRProofLibHarness();
    }

    function testFuzz_blockLeafHasherImplementations(Types.BlockLeaf memory leaf, uint256) public {
        bytes32 hashedLeafFFI = _hashBlockLeafFFI(leaf);
        bytes32 hashedLeafSolidity = leaf.hash();
        assertEq(hashedLeafFFI, hashedLeafSolidity);
    }

    function testFuzz_verifyMMRProof(uint32 blockHeight, uint256) public {
        // Generate a MMR proof using the sdk
        blockHeight = uint32(bound(blockHeight, 0, 100)); // no benefit to making this huge, just slower
        Types.MMRProof memory proof = _generateFakeBlockMMRProofFFI(blockHeight);

        bool verified = harness.verifyProof(
            proof.blockLeaf.hash(),
            proof.blockLeaf.height,
            proof.siblings,
            proof.peaks,
            proof.leafCount,
            proof.mmrRoot
        );

        assertEq(verified, true, "proveBlockInclusion failed");
    }
}
