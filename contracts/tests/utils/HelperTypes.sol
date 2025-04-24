// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;
import {BlockLeaf} from "../../src/interfaces/IBitcoinLightClient.sol";

interface HelperTypes {
    // Test-specific helper structs. Used for exposing a solidity interface to rust utils lib.
    struct MMRProof {
        BlockLeaf blockLeaf;
        bytes32[] siblings;
        bytes32[] peaks;
        uint32 leafCount;
        bytes32 mmrRoot;
    }

    struct ReleaseMMRProof {
        MMRProof proof;
        MMRProof tipProof;
    }

    struct DeploymentParams {
        bytes32 mmrRoot;
        bytes32 circuitVerificationKey;
        BlockLeaf tipBlockLeaf;
    }

    function expose() external view returns (
        MMRProof memory mmrProof,
        ReleaseMMRProof memory releaseMmrProof,
        DeploymentParams memory deploymentParams
    );

}