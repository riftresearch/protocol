// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

import {Order, Payment} from "../interfaces/IRiftExchange.sol";
import {BlockLeaf} from "../interfaces/IBitcoinLightClient.sol";
import {DutchAuction} from "../interfaces/IBTCDutchAuctionHouse.sol";

/**
 * @title HashLib
 * @notice Library for hashing structs
 */
library HashLib {
    function hash(Order memory order) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(order));
    }

    function hash(Payment memory payment) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(payment));
    }

    // TODO: determine if this is cheaper than just abi.encode'ing the struct
    // 288 vs 454 gas, abi.encode is 57% more expensive
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
