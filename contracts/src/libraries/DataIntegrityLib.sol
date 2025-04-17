// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {Types} from "./Types.sol";
import {Constants} from "./Constants.sol";
import {Errors} from "./Errors.sol";
import {HashLib} from "./HashLib.sol";

library DataIntegrityLib {
    using HashLib for Types.DepositVault;
    using HashLib for Types.ProposedSwap;

    function checkIntegrity(
        Types.DepositVault calldata vault,
        bytes32[] storage vaultHashes
    ) internal view returns (bytes32) {
        bytes32 vaultHash = vault.hash();
        if (vaultHash != vaultHashes[vault.vaultIndex]) {
            revert Errors.DepositVaultDoesNotExist();
        }
        return vaultHash;
    }

    function checkIntegrity(
        Types.ProposedSwap calldata swap,
        bytes32[] storage swapHashes
    ) internal view returns (bytes32) {
        bytes32 swapHash = swap.hash();
        if (swapHash != swapHashes[swap.swapIndex]) {
            revert Errors.SwapDoesNotExist();
        }
        return swapHash;
    }
}
