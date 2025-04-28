// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

import {IRiftAuctionAdaptor} from "./interfaces/IRiftAuctionAdaptor.sol";
import {BaseCreateOrderParams} from "./interfaces/IRiftExchange.sol";
import {DutchAuctionParams} from "./interfaces/IBTCDutchAuctionHouse.sol";

import {CoreAdapter} from "bundler3/src/adapters/CoreAdapter.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import {FixedPointMathLib} from "solady/src/utils/FixedPointMathLib.sol";

import {BTCDutchAuctionHouse} from "./BTCDutchAuctionHouse.sol";

/**
 * @title RiftAuctionAdaptor
 * @notice An adaptor for creating auctions on the BTCDutchAuctionHouse using the adaptor's tokenized BTC balance.
 * @notice sBTC is an arbitrary ERC20 token that represents BTC.
 */
contract RiftAuctionAdaptor is IRiftAuctionAdaptor, CoreAdapter {
    using SafeTransferLib for address;
    using FixedPointMathLib for uint256;

    address public immutable syntheticBitcoin;
    address public immutable btcAuctionHouse;

    constructor(address _bundler3, address _btcAuctionHouse) CoreAdapter(_bundler3) {
        btcAuctionHouse = _btcAuctionHouse;
        syntheticBitcoin = BTCDutchAuctionHouse(_btcAuctionHouse).syntheticBitcoin();
    }

    /// @inheritdoc IRiftAuctionAdaptor
    function createAuction(
        uint256 startsBTCperBTCRate,
        uint256 endcbsBTCperBTCRate,
        uint64 decayBlocks,
        uint64 deadline,
        address fillerWhitelistContract,
        BaseCreateOrderParams calldata baseParams
    ) external onlyBundler3 {
        address _syntheticBitcoin = syntheticBitcoin;
        address _btcAuctionHouse = btcAuctionHouse;
        uint256 syntheticBitcoinBalance = _syntheticBitcoin.balanceOf(address(this));

        (uint256 startAmount, uint256 endAmount) = _computeAuctionRange(
            startsBTCperBTCRate,
            endcbsBTCperBTCRate,
            syntheticBitcoinBalance
        );

        _syntheticBitcoin.safeApprove(_btcAuctionHouse, syntheticBitcoinBalance);

        // Start the auction
        BTCDutchAuctionHouse(_btcAuctionHouse).startAuction(
            syntheticBitcoinBalance,
            DutchAuctionParams({
                startBtcOut: startAmount,
                endBtcOut: endAmount,
                decayBlocks: decayBlocks,
                deadline: deadline,
                fillerWhitelistContract: fillerWhitelistContract
            }),
            baseParams
        );
    }

    /// @notice Calculates the start and end BTC output amounts for the auction.
    /// @param startsBTCperBTCRate The starting sBTC per BTC rate (WAD 1e18).
    /// @param endcbsBTCperBTCRate The ending sBTC per BTC rate (WAD 1e18).
    /// @param depositAmount The amount of sBTC being auctioned.
    /// @return startAmount The calculated starting BTC output amount.
    /// @return endAmount The calculated ending BTC output amount.
    function _computeAuctionRange(
        uint256 startsBTCperBTCRate,
        uint256 endcbsBTCperBTCRate,
        uint256 depositAmount
    ) private pure returns (uint256 startAmount, uint256 endAmount) {
        startAmount = startsBTCperBTCRate.mulWad(depositAmount);
        endAmount = endcbsBTCperBTCRate.mulWad(depositAmount);
    }
}
