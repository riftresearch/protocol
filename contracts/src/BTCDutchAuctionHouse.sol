// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

import "./interfaces/IBTCDutchAuctionHouse.sol";
import {CreateOrderParams} from "./interfaces/IRiftExchange.sol";

import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";

import {DutchDecayLib} from "./libraries/DutchDecayLib.sol";

import {HashLib} from "./libraries/HashLib.sol";
import {DataIntegrityLib} from "./libraries/DataIntegrityLib.sol";
import {RiftExchange} from "./RiftExchange.sol";
import {IRiftWhitelist} from "./interfaces/IRiftWhitelist.sol";

/**
 * @title BTCDutchAuctionHouse
 * @notice A Dutch auction for Synthetic BTC -> BTC swaps, utilizes the RiftExchange to create orders
 */
contract BTCDutchAuctionHouse is IBTCDutchAuctionHouse, RiftExchange {
    using HashLib for DutchAuction;
    using DataIntegrityLib for DutchAuction;
    using SafeTransferLib for address;

    bytes32[] public auctionHashes;

    constructor(
        bytes32 _mmrRoot,
        address _syntheticBitcoin,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        uint16 _takerFeeBips,
        BlockLeaf memory _tipBlockLeaf
    )
        RiftExchange(
            _mmrRoot,
            _syntheticBitcoin,
            _circuitVerificationKey,
            _verifier,
            _feeRouter,
            _takerFeeBips,
            _tipBlockLeaf
        )
    {}

    /// @inheritdoc IBTCDutchAuctionHouse
    function startAuction(
        uint256 depositAmount,
        DutchAuctionParams memory auctionParams,
        BaseCreateOrderParams calldata baseCreateOrderParams
    ) external {
        if (auctionParams.decayBlocks == 0) {
            revert InvalidTickSize();
        }

        if (auctionParams.startBtcOut <= auctionParams.endBtcOut) {
            revert InvalidAuctionRange();
        }

        if (auctionParams.deadline < block.timestamp) {
            revert InvalidDeadline();
        }

        DutchAuction memory auction = DutchAuction({
            index: auctionHashes.length,
            baseCreateOrderParams: baseCreateOrderParams,
            dutchAuctionParams: auctionParams,
            depositAmount: depositAmount,
            startBlock: block.number,
            startTimestamp: block.timestamp,
            state: DutchAuctionState.Created
        });

        auctionHashes.push(auction.hash());

        syntheticBitcoin.safeTransferFrom(msg.sender, address(this), depositAmount);

        emit AuctionUpdated(auction);
    }

    /// @inheritdoc IBTCDutchAuctionHouse
    function claimAuction(
        DutchAuction memory auction,
        bytes memory fillerAuthData,
        bytes32[] calldata safeBlockSiblings,
        bytes32[] calldata safeBlockPeaks
    ) external {
        auction.checkIntegrity(auctionHashes);
        if (auction.state == DutchAuctionState.Filled || auction.state == DutchAuctionState.Refunded) {
            revert AuctionNotLive();
        }
        if (auction.dutchAuctionParams.deadline < block.timestamp) {
            revert AuctionExpired();
        }
        if (auction.dutchAuctionParams.fillerWhitelistContract != address(0)) {
            if (
                !IRiftWhitelist(auction.dutchAuctionParams.fillerWhitelistContract).isWhitelisted(
                    msg.sender,
                    fillerAuthData
                )
            ) {
                revert FillerNotWhitelisted();
            }
        }

        uint256 currentBtcOut = DutchDecayLib.linearDecay({
            startPoint: auction.startBlock,
            endPoint: auction.startBlock + auction.dutchAuctionParams.decayBlocks,
            currentPoint: block.number,
            startAmount: auction.dutchAuctionParams.startBtcOut,
            endAmount: auction.dutchAuctionParams.endBtcOut
        });

        CreateOrderParams memory createOrderParams = CreateOrderParams({
            base: auction.baseCreateOrderParams,
            designatedReceiver: msg.sender,
            depositAmount: auction.depositAmount,
            expectedSats: uint64(currentBtcOut),
            safeBlockSiblings: safeBlockSiblings,
            safeBlockPeaks: safeBlockPeaks
        });

        // Note:  _createOrder takes care of accounting for tokens deposited via startAuction.
        // so no additional ERC20 transfer is necessary.
        _createOrder(createOrderParams);

        auction.state = DutchAuctionState.Filled;
        auctionHashes[auction.index] = auction.hash();
        emit AuctionUpdated(auction);
    }

    /// @inheritdoc IBTCDutchAuctionHouse
    function refundAuction(DutchAuction memory auction) external {
        auction.checkIntegrity(auctionHashes);
        if (auction.state == DutchAuctionState.Filled || auction.state == DutchAuctionState.Refunded) {
            revert AuctionNotLive();
        }
        if (auction.dutchAuctionParams.deadline > block.timestamp) {
            revert AuctionNotExpired();
        }

        // Refund auction
        auction.state = DutchAuctionState.Refunded;
        auctionHashes[auction.index] = auction.hash();

        syntheticBitcoin.safeTransfer(auction.baseCreateOrderParams.owner, auction.depositAmount);

        emit AuctionUpdated(auction);
    }
}
