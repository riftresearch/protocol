// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.28;

import {Types} from "./libraries/Types.sol";
import {RiftExchange} from "./RiftExchange.sol";

contract RiftReactor is RiftExchange {
    // min penalty for not resolving an order
    // ~25 USD worth of cbBTC,
    uint96 public constant MIN_BOND = 0.0003 * 10 ** 8;
    uint16 public constant BOND_BIPS = 100;
    // effectively, if a user has to withdraw, we slash the MM that originally
    // executed the intent. A portion of the bond goes to Rift determined by:
    uint16 public constant SLASH_FEE_BIPS = 500;
    uint256 public slashedBondFees;

    struct BondedSwap {
        // binpack both of these into a single 256 bit word
        address marketMaker;
        uint96 bond;
    }

    mapping(bytes32 => BondedSwap) public swapBonds;
    mapping(address => uint256) public intentNonce;

    struct DutchAuctionInfo {
        uint256 startBlock;
        uint256 endBlock;
        uint256 minSats;
        uint256 maxSats;
    }

    struct IntentInfo {
        address intentReactor;
        // replay protection + cancellation
        uint256 nonce;
        // this will be the cbBTC address if no swap will occur
        address tokenIn;
        DutchAuctionInfo auction;
        // a place holder, this is basically Types.DepositLiquidityParams but without
        // expectedSats, specifiedPayoutAddress
        bytes depositLiquidityParams;
    }

    struct LiquidityRoute {
        address router;
        bytes routeData;
    }

    struct SignedIntent {
        IntentInfo info; // this is signed
        bytes signature; // this is the signature of the user
        bytes32 orderHash; // do we need this?, depends on intent validation logic
    }

    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        Types.BlockLeaf memory _tipBlockLeaf
    ) RiftExchange(_mmrRoot, _depositToken, _circuitVerificationKey, _verifier, _feeRouter, _tipBlockLeaf) {
        // Initialize RiftReactor
    }

    // Note, non-exhaustive list of checks is included below
    // investigate uniswapx's implementation for all intent edge cases
    // that are relevant to check for.
    // 1. Validate intent aka SignedIntent (EIP712 typed data validation)
    // 2. Validate order is active, auction isn't over (endBlock > block.number), nonce is valid
    // 3. Validate sufficient cbBTC bond has been posted by msg.sender (the MM)
    // 4. Permit2 transfer ERC20 into reactor
    // 5. fetch contracts current balance of cbBTC, (preCallcbBTC)
    // 6. Give approval to callback contract for ERC20
    // 7. Call solver provided router with routeCalldata
    // 8. Validate sufficient cbBTC was sent
    //	  ((postCallcbBTC - preCallcbBTC) >= order.depositLiquidtyParams.depositAmount)
    // 9. Compute expected sats based on linear model defined in above footnotes.
    //10. Build final deposit call using calculated expectedSats, msg.sender for
    //    specifiedPayoutAddress and original user signed deposit data.
    //11. Call depositLiquidity()/depositLiquidityWithOverwrite()
    function executeIntentWithSwap(LiquidityRoute memory route, SignedIntent memory order) external {
        // 1. Validate intent aka SignedIntent (EIP712 typed data validation)
    }

    // For pure cbBTC deposits:
    // Steps 1-3 and 9-10 from executeIntentWithSwap()
    function executeIntent(SignedIntent memory order) external {}

    // calls releaseLiquidityBatch() and releases bond back to mm
    // should accept an array of release requests to align with the underlying
    // releaseLiquidityBatch() function
    function releaseAndFree() external {}

    // Withdraws liquidity for a deposit while applying a penalty based on SLASH_FEE_BIPS
    // A portion of the bond associated with this deposit is retained in the contract
    // as a penalty, tracked by updating `slashedBondFees` using `SLASH_FEE_BIPS`
    // The remaining bond amount is sent to the depositor's address
    function withdrawAndPenalize() external {}

    // higher of (BOND_BIPS of depositAmount) or MIN_BOND
    /**
     * @notice Computes the bond required for a given deposit amount.
     * @dev The bond is the greater of (depositAmount * BOND_BIPS / 10,000) or MIN_BOND.
     *      Integer math is used, so any fractional part is truncated, which may lead to minor rounding differences.
     * @param depositAmount The amount for which the bond is being computed.
     * @return requiredBond The required bond as a uint96.
     */
    function computeBond(uint256 depositAmount) internal pure returns (uint96 requiredBond) {
        uint256 calculatedBond = (depositAmount * BOND_BIPS) / 10000;
        if (calculatedBond < MIN_BOND) {
            return MIN_BOND;
        } else {
            return uint96(calculatedBond);
        }
    }

    /**
     * @notice Computes the expected sats (price) at the current block using a linear (Dutch Auction) decay model.
     * @dev The price decays linearly from maxSats to minSats between startBlock and endBlock.
     *      - If the current block is before startBlock, maxSats is returned.
     *      - If the current block is after endBlock, minSats is returned.
     *      The calculation uses integer arithmetic for interpolation, so division truncation may result in minor precision loss.
     * @param info A DutchAuctionInfo struct containing startBlock, endBlock, minSats, and maxSats.
     * @return expectedSats The computed expected sats value at the current block.
     */
    function computeAuctionSats(DutchAuctionInfo memory info) internal view returns (uint256 expectedSats) {
        uint256 currentBlock = block.number;

        // Return maxSats if auction hasn't started yet.
        if (currentBlock <= info.startBlock) {
            return info.maxSats;
        }
        // Return minSats if auction has already ended.
        if (currentBlock >= info.endBlock) {
            return info.minSats;
        }

        // Calculate the proportion of blocks elapsed in the auction period.
        uint256 elapsed = currentBlock - info.startBlock;
        uint256 duration = info.endBlock - info.startBlock;
        uint256 diff = info.maxSats - info.minSats;

        // Linearly interpolate to determine the current sats value.
        expectedSats = info.maxSats - ((diff * elapsed) / duration);
    }
}
