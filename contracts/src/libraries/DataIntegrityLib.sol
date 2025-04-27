// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {HashLib} from "./HashLib.sol";
import {Order, Payment} from "../interfaces/IRiftExchange.sol";
import {DutchAuction} from "../interfaces/IBTCDutchAuctionHouse.sol";

library DataIntegrityLib {
    using HashLib for Order;
    using HashLib for Payment;
    using HashLib for DutchAuction;

    error OrderDoesNotExist();
    error PaymentDoesNotExist();
    error DutchAuctionDoesNotExist();

    function checkIntegrity(
        Order calldata order,
        bytes32[] storage orderHashes
    ) internal view returns (bytes32) {
        bytes32 orderHash = order.hash();
        if (orderHash != orderHashes[order.index]) {
            revert OrderDoesNotExist();
        }
        return orderHash;
    }

    function checkIntegrity(
        Payment calldata payment,
        bytes32[] storage paymentHashes
    ) internal view returns (bytes32) {
        bytes32 paymentHash = payment.hash();
        if (paymentHash != paymentHashes[payment.index]) {
            revert PaymentDoesNotExist();
        }
        return paymentHash;
    }

    function checkIntegrity(
        DutchAuction memory auction,
        bytes32[] storage auctionHashes
    ) internal view returns (bytes32) {
        bytes32 auctionHash = auction.hash();
        if (auctionHash != auctionHashes[auction.index]) {
            revert DutchAuctionDoesNotExist();
        }
        return auctionHash;
    }
}
