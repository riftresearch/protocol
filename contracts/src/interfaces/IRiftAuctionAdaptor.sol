// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.28;

import {BaseCreateOrderParams} from "./IRiftExchange.sol";

/**
 * @title Interface for the RiftAuctionAdaptor contract
 */
interface IRiftAuctionAdaptor {
    /// @notice Returns the address of the tokenized BTC token contract used by the adaptor.
    /// @return address of the tokenizedBitcoin token.
    function tokenizedBitcoin() external view returns (address);

    /// @notice Returns the address of the BTC Dutch Auction House contract targeted by the adaptor.
    /// @return address of the BTCDutchAuctionHouse.
    function btcAuctionHouse() external view returns (address);

    /// @notice Creates a Dutch auction on the BTCDutchAuctionHouse using the adaptor's tokenizedBitcoin balance.
    /// @dev Assumes tokenizedBitcoin (sBTC) has already been transferred to this contract.
    /// @param startsBTCperBTCRate The starting sBTC per BTC rate (WAD 1e18).
    /// @param endcbsBTCperBTCRate The ending sBTC per BTC rate (WAD 1e18).
    /// @param decayBlocks The number of blocks over which the auction price decays.
    /// @param deadline The timestamp after which the auction expires.
    /// @param fillerWhitelistContract Optional contract to whitelist auction fillers.
    /// @param baseParams Base parameters for the liquidity deposit.
    function createAuction(
        uint256 startsBTCperBTCRate,
        uint256 endcbsBTCperBTCRate,
        uint64 decayBlocks,
        uint64 deadline,
        address fillerWhitelistContract,
        BaseCreateOrderParams calldata baseParams
    ) external;
}
