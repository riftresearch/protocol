// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import "./interfaces/IBTCDutchAuctionHouse.sol";
import {DepositLiquidityParams} from "./interfaces/IRiftExchange.sol";

import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";

import {DutchDecayLib} from "./libraries/DutchDecayLib.sol";

import {HashLib} from "./libraries/HashLib.sol";
import {DataIntegrityLib} from "./libraries/DataIntegrityLib.sol";
import {RiftExchange} from "./RiftExchange.sol";
import {IRiftWhitelist} from "./interfaces/IRiftWhitelist.sol";



/// @title BTCDutchAuctionHouse
/// @notice A Dutch auction for ERC20 BTC<>BTC swaps
contract BTCDutchAuctionHouse is IBTCDutchAuctionHouse, RiftExchange {
    using HashLib for DutchAuction;
    using DataIntegrityLib for DutchAuction;
    using SafeTransferLib for address;

    bytes32[] public auctionHashes;

    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        uint16 _takerFeeBips,
        BlockLeaf memory _tipBlockLeaf
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
        DutchAuctionParams memory auctionParams,
        BaseDepositLiquidityParams calldata baseDepositParams
    ) external {
        if (auctionParams.decayBlocks == 0) {
            revert InvalidTickSize();
        }

        if (auctionParams.startBtcOut <= auctionParams.endBtcOut) {
            revert InvalidStartBtcOut();
        }

        if(auctionParams.deadline < block.timestamp) {
            revert InvalidDeadline();
        }

        DutchAuction memory auction = DutchAuction({
            auctionIndex: auctionHashes.length,
            baseDepositParams: baseDepositParams,
            dutchAuctionParams: auctionParams,
            depositAmount: depositAmount,
            startBlock: block.number,
            startTimestamp: block.timestamp,
            state: DutchAuctionState.Created
        });
   
        auctionHashes.push(auction.hash());
        emit AuctionUpdated(auction);

        ERC20_BTC.safeTransferFrom(msg.sender, address(this), depositAmount);
    }

    // 1. validate the auction is live (not already filled/expired)
    // 2. call depositLiquidity()
    function fillAuction(
        DutchAuction memory auction,
        bytes memory fillerAuthData,
        bytes32[] calldata safeBlockSiblings,
        bytes32[] calldata safeBlockPeaks
    ) external {
        auction.checkIntegrity(auctionHashes);
        if (auction.state == DutchAuctionState.Filled) {
            revert AuctionAlreadyFilled();
        }
        if (auction.dutchAuctionParams.deadline < block.timestamp) {
            revert AuctionExpired();
        }
        if (auction.dutchAuctionParams.fillerWhitelistContract != address(0)) {
            if (!IRiftWhitelist(auction.dutchAuctionParams.fillerWhitelistContract).isWhitelisted(msg.sender, fillerAuthData)) {
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

        DepositLiquidityParams memory depositLiquidityParams = DepositLiquidityParams({
            base: auction.baseDepositParams,
            specifiedPayoutAddress: msg.sender,
            depositAmount: auction.depositAmount,
            expectedSats: uint64(currentBtcOut),
            safeBlockSiblings: safeBlockSiblings,
            safeBlockPeaks: safeBlockPeaks
        });

        // Note:  _depositLiquidity takes care of accounting for tokens deposited via fillAuction.
        // so no additional ERC20 deposit is necessary.
        _depositLiquidity(depositLiquidityParams);

        auction.state = DutchAuctionState.Filled;
        auctionHashes[auction.auctionIndex] = auction.hash();
        emit AuctionUpdated(auction);
    }


    // 1. validate the auction is expired
    // 2. Withdraw deposit token to depositOwnerAddress
    function withdrawFromExpiredAuction(DutchAuction memory auction) external {
        auction.checkIntegrity(auctionHashes);
        if (auction.state == DutchAuctionState.Filled) {
            revert AuctionAlreadyFilled();
        }
        if (auction.state == DutchAuctionState.Withdrawn) {
            revert AuctionAlreadyWithdrawn();
        }
        if (auction.dutchAuctionParams.deadline > block.timestamp) {
            revert AuctionNotExpired();
        }

        auction.state = DutchAuctionState.Withdrawn;
        auctionHashes[auction.auctionIndex] = auction.hash();
        emit AuctionUpdated(auction);

        ERC20_BTC.safeTransfer(auction.baseDepositParams.depositOwnerAddress, auction.depositAmount);
    }
}
