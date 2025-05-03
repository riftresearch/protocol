// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

import {IRiftExchange, BaseCreateOrderParams} from "./IRiftExchange.sol";
import {BlockLeaf} from "./IBitcoinLightClient.sol";

enum DutchAuctionState {
    Created,
    Filled,
    Refunded
}

struct DutchAuction {
    // The index of the auction in the auction hash array
    uint256 index;
    // The base parameters for the auction, to be used when the order is created
    BaseCreateOrderParams baseCreateOrderParams;
    // The parameters that define the Dutch auction (start/end amounts, decay, deadline)
    DutchAuctionParams dutchAuctionParams;
    // The amount of ERC‑20 BTC (sat‑denominated token) supplied by the auction creator
    uint256 depositAmount;
    // The block number at which the auction was started
    uint256 startBlock;
    // The timestamp at which the auction was started
    uint256 startTimestamp;
    // The state of the auction
    DutchAuctionState state;
}

struct DutchAuctionParams {
    // The starting amount of BTC the auction will sell
    uint256 startBtcOut;
    // The ending amount of BTC the auction will sell
    uint256 endBtcOut;
    // The number of blocks price will decay over
    uint256 decayBlocks;
    // The deadline of the auction (as a timestamp)
    uint256 deadline;
    // The whitelist contract to use for validating the filler
    address fillerWhitelistContract;
}

/**
 * @title Interface for the BTCDutchAuctionHouse contract
 */
interface IBTCDutchAuctionHouse is IRiftExchange {
    error InvalidTickSize();
    error InvalidStartBtcOut();
    error InvalidDeadline();
    error AuctionExpired();
    error AuctionNotLive();
    error AuctionNotExpired();
    error FillerNotWhitelisted();

    event AuctionUpdated(DutchAuction auction);

    /// @notice Returns the hash of the auction at the specified index.
    /// @param index The index of the auction.
    /// @return auctionHash hash of the auction struct.
    function auctionHashes(uint256 index) external view returns (bytes32 auctionHash);

    /// @notice Starts a new Dutch auction.
    /// @param depositAmount     Amount of ERC‑20 BTC (sat‑denominated token) supplied by the auction creator.
    /// @param auctionParams     Parameters that define the Dutch auction (start/end amounts, decay, deadline).
    /// @param baseCreateOrderParams Standard RiftExchange create‑order parameters.
    function startAuction(
        uint256 depositAmount,
        DutchAuctionParams calldata auctionParams,
        BaseCreateOrderParams calldata baseCreateOrderParams
    ) external;

    /// @notice Fills a live Dutch auction at the current price.
    /// @param auction            Full auction struct (must match on‑chain hash).
    /// @param fillerAuthData     Optional auth payload checked against a whitelist.
    /// @param safeBlockSiblings  Merkle siblings proving the "safe" block leaf used in the auction's base params.
    /// @param safeBlockPeaks     Merkle peaks proving the "safe" block path used in the auction's base params.
    function claimAuction(
        DutchAuction calldata auction,
        bytes calldata fillerAuthData,
        bytes32[] calldata safeBlockSiblings,
        bytes32[] calldata safeBlockPeaks
    ) external;

    /// @notice Refunds the creator's deposit from an un‑filled, expired auction.
    /// @param auction Full auction struct (must match on‑chain hash).
    function refundAuction(DutchAuction calldata auction) external;
}
