// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;
import {BlockLeaf} from "../../src/interfaces/IBitcoinLightClient.sol";

// These are for getting compilation artifacts for the bundler3 contracts:
import {Bundler3} from "bundler3/src/Bundler3.sol";
import {GeneralAdapter1} from "bundler3/src/adapters/GeneralAdapter1.sol";
import {ParaswapAdapter} from "bundler3/src/adapters/ParaswapAdapter.sol";


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

    function expose()
        external
        view
        returns (
            MMRProof memory mmrProof,
            ReleaseMMRProof memory releaseMmrProof,
            DeploymentParams memory deploymentParams
        );
}
