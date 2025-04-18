// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";

import {Types} from "./libraries/Types.sol";
import {Events} from "./libraries/Events.sol";
import {Errors} from "./libraries/Errors.sol";

import {HashLib} from "./libraries/HashLib.sol";
import {DataIntegrityLib} from "./libraries/DataIntegrityLib.sol";
import {RiftExchange} from "./RiftExchange.sol";

/// @title BTCDutchAuctionHouse
/// @notice A Dutch auction for ERC20 BTC<>BTC swaps
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
            dutchAuctionParams: auctionParams,
            depositAmount: depositAmount,
            startBlock: block.number,
            startTimestamp: uint64(block.timestamp),
            state: Types.DutchAuctionState.Created
        });
        Types.DutchAuction[] memory auctions = new Types.DutchAuction[](1);
        auctions[0] = auction;

        _updateAuctions(auctions, Types.DutchAuctionState.Created);

        ERC20_BTC.safeTransferFrom(msg.sender, address(this), depositAmount);
    }

    function _updateAuctions(Types.DutchAuction[] memory auctions, Types.DutchAuctionState state) private {
        for (uint256 i = 0; i < auctions.length; i++) {
            auctionHashes.push(auctions[i].hash());
        }
        emit Events.AuctionsUpdated(auctions, state);
    }

    // 1. validate the auction is live (not already filled/expired)
    // 2. call depositLiquidity()
    function fillAuction(
        Types.DutchAuction memory auction,
        bytes32[] calldata safeBlockSiblings,
        bytes32[] calldata safeBlockPeaks
    ) external {
        auction.checkIntegrity(auctionHashes);
        if (auction.state == Types.DutchAuctionState.Filled) {
            revert Errors.AuctionAlreadyFilled();
        }
        if (auction.dutchAuctionParams.deadline < block.timestamp) {
            revert Errors.AuctionExpired();
        }

        uint64 currentBtcOut = _computeCurrentSats(auction.startBlock, auction.dutchAuctionParams);

        Types.DepositLiquidityParams memory depositLiquidityParams = Types.DepositLiquidityParams({
            base: auction.baseDepositParams,
            specifiedPayoutAddress: msg.sender,
            depositAmount: auction.depositAmount,
            expectedSats: currentBtcOut,
            safeBlockSiblings: safeBlockSiblings,
            safeBlockPeaks: safeBlockPeaks
        });

        auction.state = Types.DutchAuctionState.Filled;
        Types.DutchAuction[] memory auctions = new Types.DutchAuction[](1);
        auctions[0] = auction;
        _updateAuctions(auctions, Types.DutchAuctionState.Filled);

        depositLiquidity(depositLiquidityParams);
    }

    /// @notice Computes the current output amount of sats for the auction
    /// @param startBlock The block number the auction started
    /// @param auctionParams The auction parameters
    /// @return currentPrice The current output amount of sats 
    function _computeCurrentSats(
        uint256 startBlock,
        Types.DutchAuctionParams memory auctionParams
    ) internal view returns (uint64) {
        uint64 elapsedTicks = uint64(block.number - startBlock);
        if (elapsedTicks > auctionParams.ticks) {
            elapsedTicks = auctionParams.ticks;
        }
        uint64 currentPrice = auctionParams.startBtcOut;
        uint64 priceDecrease = elapsedTicks * auctionParams.tickSize;
        currentPrice = currentPrice - priceDecrease;
        return currentPrice;
    }

    // 1. validate the auction is expired
    // 2. Withdraw deposit token to depositOwnerAddress
    function withdrawFromExpiredAuction(Types.DutchAuction memory auction) external {
        auction.checkIntegrity(auctionHashes);
        if (auction.state == Types.DutchAuctionState.Filled) {
            revert Errors.AuctionAlreadyFilled();
        }
        if (auction.state == Types.DutchAuctionState.Withdrawn) {
            revert Errors.AuctionAlreadyWithdrawn();
        }
        if (auction.dutchAuctionParams.deadline > block.timestamp) {
            revert Errors.AuctionNotExpired();
        }

        auction.state = Types.DutchAuctionState.Withdrawn;
        Types.DutchAuction[] memory auctions = new Types.DutchAuction[](1);
        auctions[0] = auction;
        _updateAuctions(auctions, Types.DutchAuctionState.Withdrawn);

        ERC20_BTC.safeTransfer(auction.baseDepositParams.depositOwnerAddress, auction.depositAmount);
    }
}
