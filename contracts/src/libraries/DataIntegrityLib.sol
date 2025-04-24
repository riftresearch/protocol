// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {HashLib} from "./HashLib.sol";
import {DepositVault} from "../interfaces/IRiftExchange.sol";
import {ProposedSwap} from "../interfaces/IRiftExchange.sol";
import {DutchAuction} from "../interfaces/IBTCDutchAuctionHouse.sol";

library DataIntegrityLib {
    using HashLib for DepositVault;
    using HashLib for ProposedSwap;
    using HashLib for DutchAuction;

    error DepositVaultDoesNotExist();
    error SwapDoesNotExist();
    error DutchAuctionDoesNotExist();

    function checkIntegrity(
        DepositVault calldata vault,
        bytes32[] storage vaultHashes
    ) internal view returns (bytes32) {
        bytes32 vaultHash = vault.hash();
        if (vaultHash != vaultHashes[vault.vaultIndex]) {
            revert DepositVaultDoesNotExist();
        }
        return vaultHash;
    }

    function checkIntegrity(
        ProposedSwap calldata swap,
        bytes32[] storage swapHashes
    ) internal view returns (bytes32) {
        bytes32 swapHash = swap.hash();
        if (swapHash != swapHashes[swap.swapIndex]) {
            revert SwapDoesNotExist();
        }
        return swapHash;
    }

    function checkIntegrity(
        DutchAuction memory auction,
        bytes32[] storage auctionHashes
    ) internal view returns (bytes32) {
        bytes32 auctionHash = auction.hash();
        if (auctionHash != auctionHashes[auction.auctionIndex]) {
            revert DutchAuctionDoesNotExist();
        }
        return auctionHash;
    }
}
