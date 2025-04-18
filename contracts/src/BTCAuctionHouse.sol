// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";

import {Types} from "./libraries/Types.sol";
import {Events} from "./libraries/Events.sol";
import {Errors} from "./libraries/Errors.sol";

import {HashLib} from "./libraries/HashLib.sol";
import {DataIntegrityLib} from "./libraries/DataIntegrityLib.sol";
import {RiftExchange} from "./RiftExchange.sol";

contract BTCDutchAuctionHouse is RiftExchange {
    using HashLib for Types.DutchAuction;
    using DataIntegrityLib for Types.DutchAuction;
    using SafeTransferLib for address;

    bytes32[] public auctionHashes;

    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        uint16 _takerFeeBips,
        Types.BlockLeaf memory _tipBlockLeaf
    )
        RiftExchange(
            _mmrRoot,
            _depositToken,
            _circuitVerificationKey,
            _verifier,
            _feeRouter,
            _takerFeeBips,
            _tipBlockLeaf
        )
    {}

    function startAuction(
        uint256 depositAmount,
        Types.DutchAuctionParams calldata auctionParams,
        Types.BaseDepositLiquidityParams calldata baseDepositParams
    ) external {
        if (auctionParams.tickSize == 0) {
            revert Errors.InvalidTickSize();
        }

        Types.DutchAuction memory auction = Types.DutchAuction({
            auctionIndex: auctionHashes.length,
            baseDepositParams: baseDepositParams,
            auctionParams: auctionParams,
            depositAmount: depositAmount,
            startBlock: block.number,
            startTimestamp: uint32(block.timestamp)
        });
        auctionHashes.push(auction.hash());
        Types.DutchAuction[] memory auctions = new Types.DutchAuction[](1);
        auctions[0] = auction;

        _updateAuctions(auctions, Types.DutchAuctionUpdateContext.Created);

        ERC20_BTC.safeTransferFrom(msg.sender, address(this), depositAmount);
    }

    function _updateAuctions(Types.DutchAuction[] memory auctions, Types.DutchAuctionUpdateContext context) private {
        for (uint256 i = 0; i < auctions.length; i++) {
            auctionHashes.push(auctions[i].hash());
        }
        emit Events.DutchAuctionsUpdated(auctions, context);
    }

    // 1. validate the auction is live (not already filled/expired)
    // 2. call depositLiquidity()
    function fillAuction(
        Types.DutchAuction calldata auction,
        bytes32[] calldata safeBlockSiblings,
        bytes32[] calldata safeBlockPeaks
    ) external {
        auction.checkIntegrity(auctionHashes);
        if (auction.auctionParams.deadline < block.timestamp) {
            revert Errors.AuctionNotLive();
        }
    }

    /// @notice Computes the current price of the auction
    /// @param auction The auction to compute the current price of
    /// @return currentPrice The current price of the auction
    function _computeCurrentPrice(Types.DutchAuction calldata auction) internal view returns (uint256) {
        uint256 currentPrice = auction.auctionParams.startBtcOut;
        uint256 ticksElapsed = block.number - auction.startBlock;
        uint256 priceDecrease = ticksElapsed * auction.auctionParams.tickSize;
        currentPrice = currentPrice - priceDecrease;
        return currentPrice;
    }

    // 1. validate the auction is expired
    // 2. Withdraw deposit token to depositOwnerAddress
    function withdrawFromExpiredAuction(uint256 auctionId) external {}
}
