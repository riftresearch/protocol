// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {BaseDepositLiquidityParams} from "./IRiftExchange.sol";

/// @title IRiftAuctionAdaptor
/// @notice Interface for the RiftAuctionAdaptor contract.
interface IRiftAuctionAdaptor {
    /// @notice Returns the address of the synthetic BTC token contract used by the adaptor.
    /// @return Address of the sBTC token.
    function sBTC() external view returns (address);

    /// @notice Returns the address of the BTC Dutch Auction House contract targeted by the adaptor.
    /// @return Address of the BTCDutchAuctionHouse.
    function btcAuctionHouse() external view returns (address);

    /// @notice Creates a Dutch auction on the BTCDutchAuctionHouse using the adaptor's sBTC balance.
    /// @dev Assumes sBTC has already been transferred to this contract.
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
        BaseDepositLiquidityParams calldata baseParams
    ) external;

    // Note: Functions inherited from CoreAdapter (like bundler3()) are not explicitly listed here
    // but would be part of the full interface if ICoreAdapter were included.
} 