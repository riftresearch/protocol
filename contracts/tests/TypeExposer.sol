// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {Types} from "../src/libraries/Types.sol";

interface TypeExposer {
    /**
     * @notice A dummy function that “exposes” all the types from the Types library.
     * The function returns a tuple containing one instance of each struct and each enum
     */
    function exposeTypes()
        external
        view
        returns (
            // --- LIGHT CLIENT TYPES ---
            Types.BlockLeaf memory blockLeaf,
            // --- EXCHANGE SETTLEMENT TYPES (Structs) ---
            Types.DepositVault memory depositVault,
            Types.ProposedSwap memory proposedSwap,
            Types.SwapPublicInput memory swapPublicInput,
            Types.LightClientPublicInput memory lightClientPublicInput,
            Types.ProofPublicInput memory proofPublicInput,
            // --- UTILITY STRUCTS ---
            Types.MMRProof memory mmrProof,
            Types.ReleaseMMRProof memory releaseMMRProof,
            // --- PARAMETER STRUCTS ---
            Types.DepositLiquidityParams memory depositLiquidityParams,
            Types.BlockProofParams memory blockProofParams,
            Types.SubmitSwapProofParams memory submitSwapProofParams,
            Types.ReleaseLiquidityParams memory releaseLiquidityParams,
            Types.DeploymentParams memory deploymentParams,
            // --- ENUMS (as their underlying type: uint8) ---
            Types.SwapState, // Represents Types.SwapState
            Types.ProofType, // Represents Types.ProofType
            Types.VaultUpdateContext, // Represents Types.VaultUpdateContext
            Types.SwapUpdateContext // Represents Types.SwapUpdateContext
        );
}
