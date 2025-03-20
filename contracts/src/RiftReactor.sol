// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.28;

import {RiftExchange} from "./RiftExchange.sol";
import {EIP712Hashing} from "./libraries/Hashing.sol";
import {Types} from "./libraries/Types.sol";
import {Errors} from "./libraries/Errors.sol";
import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {IPermit2} from "uniswap-permit2/src/interfaces/IPermit2.sol";

contract RiftReactor is RiftExchange {
    // TODO: Organize code and move out certain functions to separate libs.
    using ECDSA for bytes32;
    using EIP712Hashing for Types.IntentInfo;
    using EIP712Hashing for Types.SignedIntent;

    // min penalty for not resolving an order
    // ~25 USD worth of cbBTC,
    uint96 public constant MIN_BOND = 0.0003 * 10 ** 8;
    uint16 public constant BOND_BIPS = 100;
    // effectively, if a user has to withdraw, we slash the MM that originally
    // executed the intent. A portion of the bond goes to Rift determined by:
    uint16 public constant SLASH_FEE_BIPS = 500;
    uint256 public slashedBondFees;

    // Validation constants
    bytes32 public immutable DOMAIN_SEPARATOR;

    // Mapping to track the available bond deposited by each market maker.
    mapping(address => uint96) public mmBondDeposits;
    // Mapping to track bond associated with each executed swap.
    mapping(bytes32 => Types.BondedSwap) public swapBonds;
    // Nonce mapping: deposit owner address => nonce
    mapping(address => uint256) public intentNonce;

    IERC20 immutable cbBTC;
    IPermit2 immutable permit2;

    // TODO: Move these to error library

    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        Types.BlockLeaf memory _tipBlockLeaf,
        address _cbbtc_address,
        address _permit2
    ) RiftExchange(_mmrRoot, _depositToken, _circuitVerificationKey, _verifier, _feeRouter, _tipBlockLeaf) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("RiftReactor"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );

        cbBTC = IERC20(_cbbtc_address);
        permit2 = IPermit2(_permit2);
    }

    // ---------------------------------------------------------------
    // Modifiers
    // ---------------------------------------------------------------
    /**
     * @notice Validates the signed intent and ensures the market maker has posted sufficient bond.
     * @dev Performs these checks:
     *      1. Validates the EIP‑712 signature of the SignedIntent.
     *      2. Verifies the auction is active (auction.endBlock > block.number) and the nonce is correct.
     *      3. Checks that msg.sender (the market maker executing the swap) has posted sufficient cbBTC bond.
     *          The required bond is computed based on depositLiquidityParams.depositAmount, which now represents
     *          the expected amount of cbBTC the MM must supply.
     * @param order The SignedIntent containing the intent and signature data.
     */
    modifier validateIntentAndBond(Types.SignedIntent calldata order) {
        // NOTE: Do less gas intensive checks first, then if those fail more gas
        // will be returned.
        if (order.info.auction.endBlock <= block.number) {
            revert Errors.AuctionEnded();
        }
        if (order.info.nonce != intentNonce[order.info.depositLiquidityParams.depositOwnerAddress]) {
            revert Errors.InvalidNonce();
        }

        // Step 1: Validate the EIP‑712 signature of the SignedIntent.
        order.validateEIP712(DOMAIN_SEPARATOR);

        // Step 3: Validate that the market maker has posted sufficient bond.
        // depositAmount represents the expected amount of cbBTC the MM must supply.
        uint256 depositAmount = order.info.depositLiquidityParams.depositAmount;
        uint96 requiredBond = _computeBond(depositAmount);
        uint96 bondPosted = _getBondPosted(msg.sender);
        if (bondPosted < requiredBond) {
            revert Errors.InsufficientBond();
        }
        _;
    }

    // -----------------------------------------------------------------------
    //                   PUBLIC/EXTERNAL FUNCTIONS
    // -----------------------------------------------------------------------

    /**
     * @notice Executes a liquidity intent with an atomic swap using a provided route
     * @dev This function handles the complete flow of validating and executing a liquidity intent.
     * @dev Non-exhaustive checklist (TODO: Remove after implementation):
     *      [X] 1. Validate intent aka SignedIntent (EIP712 typed data validation)
     *      [X] 2. Validate order is active, auction isn't over (endBlock > block.number), nonce is valid
     *      [X] 3. Validate sufficient cbBTC bond has been posted by msg.sender (the MM)
     *      [X] 4. Permit2 transfer ERC20 into reactor
     *      [X] 5. Fetch contracts current balance of cbBTC (preCallcbBTC)
     *      [X] 6. Give approval to callback contract for ERC20
     *      [X] 7. Call solver provided router with routeCalldata
     *      [X] 8. Validate sufficient cbBTC was sent ((postCallcbBTC - preCallcbBTC) >= order.depositLiquidtyParams.depositAmount)
     *      [X] 9. Compute expected sats based on linear model defined in above footnotes
     *      [X] 10. Build final deposit call using calculated expectedSats, msg.sender for specifiedPayoutAddress and original user signed deposit data
     *      [X] 11. Call depositLiquidity()/depositLiquidityWithOverwrite()
     * @param route The liquidity route containing swap details and routing information
     * @param order The signed intent containing deposit parameters and permit2 transfer info
     */
    function executeIntentWithSwap(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order
    ) external validateIntentAndBond(order) {
        // Compute required bond based on the deposit amount.
        uint256 depositAmount = order.info.depositLiquidityParams.depositAmount;
        uint96 requiredBond = _computeBond(depositAmount);

        // Deduct the required bond from the MM's deposited balance.
        mmBondDeposits[msg.sender] -= requiredBond;

        // Record the bonded swap.
        bytes32 orderId = order.orderHash; // Alternatively, compute a unique identifier.
        swapBonds[orderId] = Types.BondedSwap({marketMaker: msg.sender, bond: requiredBond});
        // End step 13

        // Step 4: Transfer ERC20 tokens from the user's account into the
        // reactor using Permit2.
        IPermit2(permit2).permitTransferFrom(
            order.info.permit2TransferInfo.permitTransferFrom,
            order.info.permit2TransferInfo.transferDetails,
            order.info.permit2TransferInfo.owner,
            order.info.permit2TransferInfo.signature
        );

        // Steps 5-8: Execute the swap and validate sufficient cbBTC was received
        _executeSwap(route, order, depositAmount);

        //    ((postCallcbBTC - preCallcbBTC) >= order.depositLiquidtyParams.depositAmount)
        // 9. Compute expected sats based on linear model defined in above
        //    footnotes.
        //10. Build final deposit call using calculated expectedSats, msg.sender for
        //    specifiedPayoutAddress and original user signed deposit data.
        //11. Call depositLiquidity()/depositLiquidityWithOverwrite
        uint256 expectedSats = _computeAuctionSats(order.info.auction);
        depositLiquidity(_buildDepositLiquidityParams(order.info.depositLiquidityParams, msg.sender, expectedSats));
    }

    /**
     * @notice Executes a liquidity intent with an atomic swap using a provided route
     * @dev This function handles the complete flow of validating and executing a liquidity intent.
     * @dev Non-exhaustive checklist (TODO: Remove after implementation):
     *      [X] 1. Validate intent aka SignedIntent (EIP712 typed data validation)
     *      [X] 2. Validate order is active, auction isn't over (endBlock > block.number), nonce is valid
     *      [X] 3. Validate sufficient cbBTC bond has been posted by msg.sender (the MM)
     *      [X] 9. Compute expected sats based on linear model defined in above footnotes
     *      [X] 10. Build final deposit call using calculated expectedSats, msg.sender for specifiedPayoutAddress and original user signed deposit data
     *      [X] 11. Call depositLiquidity()/depositLiquidityWithOverwrite()
     * @param order The signed intent containing deposit parameters and permit2 transfer info
     */
    // For pure cbBTC deposits:
    // Steps 1-3 and 9-10 from executeIntentWithSwap()
    function executeIntent(Types.SignedIntent calldata order) external validateIntentAndBond(order) {
        // 9. Compute expected sats based on linear model defined in above footnotes
        //10. Build final deposit call using calculated expectedSats, msg.sender for
        //    specifiedPayoutAddress and original user signed deposit data.
        //11. Call depositLiquidity()/depositLiquidityWithOverwrite()
        uint256 expectedSats = _computeAuctionSats(order.info.auction);
        depositLiquidity(_buildDepositLiquidityParams(order.info.depositLiquidityParams, msg.sender, expectedSats));
    }

    // calls releaseLiquidityBatch() and releases bond back to mm
    // should accept an array of release requests to align with the underlying
    // releaseLiquidityBatch() function
    function releaseAndFree() external {}

    // Withdraws liquidity for a deposit while applying a penalty based on SLASH_FEE_BIPS
    // A portion of the bond associated with this deposit is retained in the contract
    // as a penalty, tracked by updating `slashedBondFees` using `SLASH_FEE_BIPS`
    // The remaining bond amount is sent to the depositor's address
    function withdrawAndPenalize() external {}

    /**
     * @notice Allows a market maker to deposit cbBTC as bond.
     * @param amount The amount of cbBTC to deposit.
     * @dev The market maker must have approved this contract to spend their cbBTC.
     */
    function depositBond(uint96 amount) external {
        bool success = cbBTC.transferFrom(msg.sender, address(this), amount);
        if (!success) {
            revert Errors.BondDepositTransferFailed();
        }
        mmBondDeposits[msg.sender] += amount;
    }

    // ---------------------------------------------------------------
    //                     INTERNAL FUNCTIONS
    // ---------------------------------------------------------------

    /**
     * @notice Executes a token swap through a router and validates the resulting cbBTC amount
     * @dev Handles steps 5-8 of the swap execution process:
     *      5. Fetch contract's current balance of cbBTC
     *      6. Approve the router contract to spend the tokens
     *      7. Call the router with the provided route data
     *      8. Validate that sufficient cbBTC was received after the swap
     * @param route The liquidity route containing swap details and routing information
     * @param order The signed intent containing deposit parameters
     * @param depositAmount The expected amount of cbBTC to receive from the swap
     */
    function _executeSwap(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order,
        uint256 depositAmount
    ) internal {
        // Step 5: Fetch contracts current balance of cbBTC (preCallcbBTC)
        uint256 preCallcbBTC = cbBTC.balanceOf(address(this));

        // Step 6: Give approval to callback contract for ERC20
        IERC20(order.info.tokenIn).approve(address(route.router), depositAmount);

        // Step 7: Call solver provided router with routeCalldata
        (bool success, ) = route.router.call(route.routeData);
        if (!success) {
            revert Errors.RouterCallFailed();
        }

        // Step 8: Validate sufficient cbBTC was sent
        uint256 postCallcbBTC = cbBTC.balanceOf(address(this));
        if ((postCallcbBTC - preCallcbBTC) < depositAmount) {
            revert Errors.InsufficientCbBTC();
        }
    }

    /**
     * @notice Builds the DepositLiquidityParams struct for deposit functions
     * @param baseParams The base deposit liquidity parameters from the order
     * @param specifiedPayoutAddress The address that will receive payout (usually the MM)
     * @param expectedSats The calculated expected satoshis based on the auction
     * @return params The fully constructed DepositLiquidityParams struct
     */
    function _buildDepositLiquidityParams(
        Types.ReactorDepositLiquidityParams calldata baseParams,
        address specifiedPayoutAddress,
        uint256 expectedSats
    ) internal pure returns (Types.DepositLiquidityParams memory params) {
        return
            Types.DepositLiquidityParams({
                depositOwnerAddress: baseParams.depositOwnerAddress,
                specifiedPayoutAddress: specifiedPayoutAddress,
                depositAmount: baseParams.depositAmount,
                expectedSats: uint64(expectedSats),
                btcPayoutScriptPubKey: baseParams.btcPayoutScriptPubKey,
                depositSalt: baseParams.depositSalt,
                confirmationBlocks: baseParams.confirmationBlocks,
                safeBlockLeaf: baseParams.safeBlockLeaf,
                safeBlockSiblings: baseParams.safeBlockSiblings,
                safeBlockPeaks: baseParams.safeBlockPeaks
            });
    }

    // ---------------------------------------------------------------
    // Bond Management Functions
    // ---------------------------------------------------------------
    /**
     * @notice Retrieves the amount of bond posted by a market maker.
     * @param mm The market maker's address.
     * @return bondAmount The available bond amount for the given market maker.
     */
    function _getBondPosted(address mm) internal view returns (uint96 bondAmount) {
        return mmBondDeposits[mm];
    }

    // -----------------------------------------------------------------------
    //                             HELPER FUNCTIONS
    // -----------------------------------------------------------------------
    // TODO Possibly replace the less precise integer math with FixedPointMathLib.
    /**
     * @notice Computes the bond required for a given deposit amount.
     * @dev The bond is the greater of (depositAmount * BOND_BIPS / 10,000) or MIN_BOND.
     *      Integer math is used, so any fractional part is truncated, which may lead to minor rounding differences.
     * @param depositAmount The amount for which the bond is being computed.
     * @return requiredBond The required bond as a uint96.
     */
    function _computeBond(uint256 depositAmount) internal pure returns (uint96 requiredBond) {
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
    function _computeAuctionSats(Types.DutchAuctionInfo calldata info) internal view returns (uint256 expectedSats) {
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
