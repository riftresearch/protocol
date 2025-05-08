// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.27;

import {Test} from "forge-std/src/Test.sol";
import {RiftTest} from "../utils/RiftTest.t.sol";

import {MMRProofLib} from "../../src/libraries/MMRProof.sol";
import {HashLib} from "../../src/libraries/HashLib.sol";
import {BlockLeaf} from "../../src/interfaces/IBitcoinLightClient.sol";
import {HelperTypes} from "../utils/HelperTypes.t.sol";

contract MMRProofLibUnitTest is RiftTest {
    using HashLib for BlockLeaf;

    function setUp() public override {
        super.setUp();
    }

    function testFuzz_blockLeafHasherImplementations(BlockLeaf memory leaf, uint256) public {
        bytes32 hashedLeafFFI = _hashBlockLeafFFI(leaf);
        bytes32 hashedLeafSolidity = leaf.hash();
        assertEq(hashedLeafFFI, hashedLeafSolidity);
    }

    function testFuzz_verifyMMRProof(uint32 blockHeight, uint256) public {
        // Generate a MMR proof using the sdk
        blockHeight = uint32(bound(blockHeight, 0, 100)); // no benefit to making this huge, just slower
        HelperTypes.MMRProof memory proof = _generateFakeBlockMMRProofFFI(blockHeight);

        bool verified = MMRProofLib.verifyProof(
            proof.blockLeaf.hash(),
            proof.blockLeaf.height,
            proof.siblings,
            proof.peaks,
            proof.leafCount,
            proof.mmrRoot
        );

        assertEq(verified, true, "proveBlockInclusion failed");
    }

    /// forge-config: default.isolate = true
    function test_verifyMMRProof_2pow3() public {
        HelperTypes.MMRProof memory proof = _generateFakeBlockMMRProofFFI(2 ** 3 - 1);
        bool verified;
        vm.startSnapshotGas("MMRProofLibTest", "verifyMMRProof_2pow3");
        verified = MMRProofLib.verifyProof(
            proof.blockLeaf.hash(),
            proof.blockLeaf.height,
            proof.siblings,
            proof.peaks,
            proof.leafCount,
            proof.mmrRoot
        );
        vm.stopSnapshotGas("MMRProofLibTest", "verifyMMRProof_2pow3");

        assertEq(verified, true, "proveBlockInclusion failed");
    }

    /// forge-config: default.isolate = true
    function test_verifyMMRProof_2pow5() public {
        // Generate a MMR proof using the sdk
        HelperTypes.MMRProof memory proof = _generateFakeBlockMMRProofFFI(2 ** 5 - 1);

        bool verified;
        vm.startSnapshotGas("MMRProofLibTest", "verifyMMRProof_2pow5");
        verified = MMRProofLib.verifyProof(
            proof.blockLeaf.hash(),
            proof.blockLeaf.height,
            proof.siblings,
            proof.peaks,
            proof.leafCount,
            proof.mmrRoot
        );
        vm.stopSnapshotGas("MMRProofLibTest", "verifyMMRProof_2pow5");

        assertEq(verified, true, "proveBlockInclusion failed");
    }

    function test_verifyMMRProof_2pow7() public {
        HelperTypes.MMRProof memory proof = _generateFakeBlockMMRProofFFI(2 ** 7 - 1);
        bool verified;
        vm.startSnapshotGas("MMRProofLibTest", "verifyMMRProof_2pow7");
        verified = MMRProofLib.verifyProof(
            proof.blockLeaf.hash(),
            proof.blockLeaf.height,
            proof.siblings,
            proof.peaks,
            proof.leafCount,
            proof.mmrRoot
        );
        vm.stopSnapshotGas("MMRProofLibTest", "verifyMMRProof_2pow7");

        assertEq(verified, true, "proveBlockInclusion failed");
    }

    /// forge-config: default.isolate = true
    function test_verifyMMRProof_2pow9() public {
        HelperTypes.MMRProof memory proof = _generateFakeBlockMMRProofFFI(2 ** 9 - 1);
        bool verified;
        vm.startSnapshotGas("MMRProofLibTest", "verifyMMRProof_2pow9");
        verified = MMRProofLib.verifyProof(
            proof.blockLeaf.hash(),
            proof.blockLeaf.height,
            proof.siblings,
            proof.peaks,
            proof.leafCount,
            proof.mmrRoot
        );
        vm.stopSnapshotGas("MMRProofLibTest", "verifyMMRProof_2pow9");

        assertEq(verified, true, "proveBlockInclusion failed");
    }
}
