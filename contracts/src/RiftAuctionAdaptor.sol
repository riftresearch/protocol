// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {CoreAdapter} from "bundler3/src/adapters/CoreAdapter.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import {FixedPointMathLib} from "solady/src/utils/FixedPointMathLib.sol";

import {BTCDutchAuctionHouse} from "./BTCDutchAuctionHouse.sol";
import {Types} from "./libraries/Types.sol";

/// @title RiftAuctionAdaptor
/// @notice An adaptor for creating auctions on the BTCDutchAuctionHouse using the adaptor's tokenized BTC balance.
/// @notice sBTC is an arbitrary ERC20 token that represents BTC.
contract RiftAuctionAdaptor is CoreAdapter {
	using SafeTransferLib for address;
	using FixedPointMathLib for uint256;

	/// @notice The synthetic BTC token contract.
	address public immutable sBTC;

	/// @notice The BTC Dutch Auction House contract.
	address public immutable btcAuctionHouse;

	// --- Constructor ---
	constructor(address _bundler3, address _btcAuctionHouse) CoreAdapter(_bundler3) {
		btcAuctionHouse = _btcAuctionHouse;
		sBTC = BTCDutchAuctionHouse(_btcAuctionHouse).ERC20_BTC();
	}

	// --- Auction ---

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
		Types.BaseDepositLiquidityParams calldata baseParams
	) external onlyBundler3 {
		address _sBTC = sBTC;
		address _btcAuctionHouse = btcAuctionHouse;
		uint256 sBTCBalance = _sBTC.balanceOf(address(this));

		(uint256 startAmount, uint256 endAmount) = _computeAuctionRange(startsBTCperBTCRate, endcbsBTCperBTCRate, sBTCBalance);

		_sBTC.safeApprove(_btcAuctionHouse, sBTCBalance);

		// Start the auction
		BTCDutchAuctionHouse(_btcAuctionHouse).startAuction(
			sBTCBalance,
			Types.DutchAuctionParams({
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