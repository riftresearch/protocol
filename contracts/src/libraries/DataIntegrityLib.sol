// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

import {HashLib} from "./HashLib.sol";
import {Order, Payment} from "../interfaces/IRiftExchange.sol";
import {DutchAuction} from "../interfaces/IBTCDutchAuctionHouse.sol";

/**
 * @title DataIntegrityLib
 * @notice Checks the integrity of data against known hashes stored as arrays
 */
library DataIntegrityLib {
    using HashLib for Order;
    using HashLib for Payment;
    using HashLib for DutchAuction;

    error OrderDoesNotExist(uint256 index);
    error PaymentDoesNotExist(uint256 index);
    error DutchAuctionDoesNotExist(uint256 index);

    function checkIntegrity(Order calldata order, bytes32[] storage orderHashes) internal view returns (bytes32) {
        bytes32 orderHash = order.hash();
        if (orderHash != orderHashes[order.index]) {
            revert OrderDoesNotExist(order.index);
        }
        return orderHash;
    }

    function checkIntegrity(Payment calldata payment, bytes32[] storage paymentHashes) internal view returns (bytes32) {
        bytes32 paymentHash = payment.hash();
        if (paymentHash != paymentHashes[payment.index]) {
            revert PaymentDoesNotExist(payment.index);
        }
        return paymentHash;
    }

    function checkIntegrity(
        DutchAuction memory auction,
        bytes32[] storage auctionHashes
    ) internal view returns (bytes32) {
        bytes32 auctionHash = auction.hash();
        if (auctionHash != auctionHashes[auction.index]) {
            revert DutchAuctionDoesNotExist(auction.index);
        }
        return auctionHash;
    }
}
