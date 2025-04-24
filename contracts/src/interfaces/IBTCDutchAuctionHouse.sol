// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {IRiftExchange, BaseDepositLiquidityParams} from "./IRiftExchange.sol";
import {BlockLeaf} from "./IBitcoinLightClient.sol";

enum DutchAuctionState {
    Created,
    Filled,
    Withdrawn
}

struct DutchAuction {
    uint256 auctionIndex;
    BaseDepositLiquidityParams baseDepositParams;
    DutchAuctionParams dutchAuctionParams;
    uint256 depositAmount;
    uint256 startBlock;
    uint256 startTimestamp;
    DutchAuctionState state;
}

struct DutchAuctionParams {
    uint256 startBtcOut; // the starting amount of BTC the auction will sell
    uint256 endBtcOut; // the ending amount of BTC the auction will sell
    uint256 decayBlocks; // the number of blocks price will decay over
    uint256 deadline; // the deadline of the auction (as a timestamp)
    address fillerWhitelistContract; // the whitelist contract to use for validating the filler
}



/// @title IBTCDutchAuctionHouse
/// @notice Interface for the BTCDutchAuctionHouse contract.
interface IBTCDutchAuctionHouse is IRiftExchange {

    event AuctionUpdated(DutchAuction auction);

    error InvalidTickSize();
    error InvalidStartBtcOut();
    error InvalidDeadline();
    error AuctionExpired();
    error AuctionAlreadyFilled();
    error AuctionAlreadyWithdrawn();
    error AuctionNotExpired();
    error FillerNotWhitelisted();

    /// @notice Returns the hash of the auction at the specified index.
    /// @param auctionIndex The index of the auction.
    /// @return The keccak256 hash of the auction struct.
    function auctionHashes(uint256 auctionIndex) external view returns (bytes32);

    /// @notice Starts a new Dutch auction.
    /// @param depositAmount     Amount of ERC‑20 BTC (sat‑denominated token) supplied by the auction creator.
    /// @param auctionParams     Parameters that define the Dutch auction (start/end amounts, decay, deadline).
    /// @param baseDepositParams Standard RiftExchange deposit‑liquidity parameters.
    function startAuction(
        uint256 depositAmount,
        DutchAuctionParams calldata auctionParams, 
        BaseDepositLiquidityParams calldata baseDepositParams 
    ) external;

    /// @notice Fills a live Dutch auction at the current price.
    /// @param auction            Full auction struct (must match on‑chain hash).
    /// @param fillerAuthData     Optional auth payload checked against a whitelist.
    /// @param safeBlockSiblings  Merkle siblings proving the "safe" block leaf used in the auction's base params.
    /// @param safeBlockPeaks     Merkle peaks proving the "safe" block path used in the auction's base params.
    function fillAuction(
        DutchAuction calldata auction, 
        bytes calldata fillerAuthData,
        bytes32[] calldata safeBlockSiblings,
        bytes32[] calldata safeBlockPeaks
    ) external;

    /// @notice Withdraws the creator's deposit from an un‑filled, expired auction.
    /// @param auction Full auction struct (must match on‑chain hash).
    function withdrawFromExpiredAuction(DutchAuction calldata auction) external;
} 