// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

import {DepositVault} from "../interfaces/IRiftExchange.sol";
import {ProposedSwap} from "../interfaces/IRiftExchange.sol";
import {BlockLeaf} from "../interfaces/IBitcoinLightClient.sol";
import {DutchAuction} from "../interfaces/IBTCDutchAuctionHouse.sol";


library HashLib {
    function hash(DepositVault memory vault) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(vault));
    }

    function hash(ProposedSwap memory swap) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(swap));
    }

    // TODO: determine if this is cheaper than just abi.encode'ing the struct
    function hash(BlockLeaf memory blockLeaf) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                blockLeaf.blockHash,
                bytes32(uint256(blockLeaf.height)),
                bytes32(blockLeaf.cumulativeChainwork)
            );
    }

    function hash(DutchAuction memory dutchAuction) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(dutchAuction));
    }
}
