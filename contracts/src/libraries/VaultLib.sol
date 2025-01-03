// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {Types} from "./Types.sol";
import {Constants} from "./Constants.sol";
import {Errors} from "./Errors.sol";

import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

library VaultLib {
    function hashDepositVault(Types.DepositVault memory vault) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(vault));
    }

    function hashSwap(Types.ProposedSwap memory swap) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(swap));
    }

    /// @notice Validates that a scriptPubKey follows the P2WPKH format (OP_0(0x00) + OP_PUSHBYTES_20(0x14) + <20-byte-pubkey-hash>)
    function validateP2WPKHScriptPubKey(bytes22 scriptPubKey) internal pure returns (bool) {
        return scriptPubKey[0] == 0x00 && scriptPubKey[1] == 0x14;
    }

    function validateDepositVaultCommitment(
        Types.DepositVault calldata vault,
        bytes32[] storage vaultCommitments
    ) internal view returns (bytes32) {
        bytes32 vaultHash = hashDepositVault(vault);
        if (vaultHash != vaultCommitments[vault.vaultIndex]) {
            revert Errors.DepositVaultDoesNotExist();
        }
        return vaultHash;
    }

    function validateSwapCommitment(
        Types.ProposedSwap calldata swap,
        bytes32[] storage swapCommitments
    ) internal view returns (bytes32) {
        bytes32 swapHash = hashSwap(swap);
        if (swapHash != swapCommitments[swap.swapIndex]) {
            revert Errors.SwapDoesNotExist();
        }
        return swapHash;
    }

    function validateDepositVaultCommitments(
        Types.DepositVault[] calldata vaults,
        bytes32[] storage vaultCommitments
    ) internal view returns (bytes32) {
        bytes32[] memory vaultHashes = new bytes32[](vaults.length);
        for (uint256 i = 0; i < vaults.length; i++) {
            vaultHashes[i] = validateDepositVaultCommitment(vaults[i], vaultCommitments);
        }
        return EfficientHashLib.hash(vaultHashes);
    }

    function getOldestAttestedBitcoinBlockHeightFromVaults(
        Types.DepositVault[] calldata vaults
    ) internal pure returns (uint64) {
        if (vaults.length == 0) {
            revert Errors.NoVaults();
        }
        uint64 oldestAttestedBitcoinBlockHeight = vaults[0].attestedBitcoinBlockHeight;
        for (uint256 i = 1; i < vaults.length; i++) {
            if (vaults[i].attestedBitcoinBlockHeight < oldestAttestedBitcoinBlockHeight) {
                oldestAttestedBitcoinBlockHeight = vaults[i].attestedBitcoinBlockHeight;
            }
        }
        return oldestAttestedBitcoinBlockHeight;
    }

    function validateConfirmationBlocksIsSufficient(
        Types.DepositVault[] calldata vaults,
        uint8 confirmationBlocks
    ) internal pure {
        for (uint256 i = 0; i < vaults.length; i++) {
            if (vaults[i].confirmationBlocks > confirmationBlocks) {
                revert Errors.NotEnoughConfirmationBlocks();
            }
        }
    }

    function validatePayoutAddressIsSameForAllVaults(
        Types.DepositVault[] calldata vaults,
        address payoutAddress
    ) internal pure {
        for (uint256 i = 0; i < vaults.length; i++) {
            if (vaults[i].specifiedPayoutAddress != payoutAddress) {
                revert Errors.PayoutAddressMismatch();
            }
        }
    }

    function calculateSwapTotals(
        Types.DepositVault[] memory vaults
    ) internal pure returns (uint256 totalSwapOutput, uint256 totalSwapFee) {
        uint256 totalDeposit = 0;
        uint256 takerFee = 0;

        for (uint256 i = 0; i < vaults.length; i++) {
            totalDeposit += vaults[i].depositAmount;
            takerFee += vaults[i].depositFee;
            totalSwapFee += vaults[i].depositFee * 2;
        }

        totalSwapOutput = totalDeposit - takerFee;
    }

    function validateSwapTotals(
        Types.DepositVault[] memory vaults,
        uint256 totalSwapFee,
        uint256 totalSwapOutput
    ) internal pure {
        (uint256 calculatedTotalSwapOutput, uint256 calculatedTotalSwapFee) = calculateSwapTotals(vaults);
        if (calculatedTotalSwapOutput != totalSwapOutput || calculatedTotalSwapFee != totalSwapFee) {
            revert Errors.InvalidSwapTotals();
        }
    }
}
