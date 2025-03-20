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

    // Mapping to track bond associated with each executed swap.
    mapping(bytes32 => Types.BondedSwap) public swapBonds;
    // Nonce mapping: deposit owner address => nonce
    mapping(address => uint256) public intentNonce;

    IERC20 immutable CB_BTC;
    IPermit2 immutable PERMIT2;

    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        Types.BlockLeaf memory _tipBlockLeaf,
        address _cbbtc_address,
        address _permit2_address
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

        CB_BTC = IERC20(_cbbtc_address);
        PERMIT2 = IPermit2(_permit2_address);
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
    // validateIntentAndBond(order)
    function executeIntentWithSwap(Types.LiquidityRoute calldata route, Types.SignedIntent calldata order) external {
        uint256 expectedSats = _executeIntentAndSwapShared(route, order);

        depositLiquidity(_buildDepositLiquidityParams(order.info.depositLiquidityParams, msg.sender, expectedSats));
        intentNonce[order.info.depositLiquidityParams.depositOwnerAddress] += 1;
    }

    /**
     * @notice Executes a liquidity intent with an atomic swap using a provided route and overwrites an existing vault
     * @dev This function handles the complete flow of validating and executing a liquidity intent,
     *      then overwrites an existing empty vault with the new deposit.
     * @param route The liquidity route containing swap details and routing information
     * @param order The signed intent containing deposit parameters and permit2 transfer info
     * @param depositVault The existing empty vault to overwrite with the new deposit
     */
    function executeIntentWithSwap(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order,
        Types.DepositVault calldata depositVault
    ) external {
        uint256 expectedSats = _executeIntentAndSwapShared(route, order);

        depositLiquidityWithOverwrite(
            Types.DepositLiquidityWithOverwriteParams({
                depositParams: _buildDepositLiquidityParams(
                    order.info.depositLiquidityParams,
                    msg.sender,
                    expectedSats
                ),
                overwriteVault: depositVault
            })
        );
        intentNonce[order.info.depositLiquidityParams.depositOwnerAddress] += 1;
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
    function executeIntent(Types.SignedIntent calldata order) external {
        _validateBondAndRecord(order);

        uint256 expectedSats = _computeAuctionSats(order.info.auction);
        depositLiquidity(_buildDepositLiquidityParams(order.info.depositLiquidityParams, msg.sender, expectedSats));
        intentNonce[order.info.depositLiquidityParams.depositOwnerAddress] += 1;
    }

    /** Shared functionality between depositLiquidity and depositLiquidityOverride */
    function _executeIntentAndSwapShared(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order
    ) internal returns (uint256 expectedSats) {
        _validateBondAndRecord(order);

        // Step 4: Transfer ERC20 tokens from the user's account into the
        // reactor using Permit2.
        PERMIT2.permitTransferFrom(
            order.info.permit2TransferInfo.permitTransferFrom,
            order.info.permit2TransferInfo.transferDetails,
            order.info.permit2TransferInfo.owner,
            order.info.permit2TransferInfo.signature
        );

        // Steps 5-8: Execute the swap and validate sufficient cbBTC was received
        _executeSwap(route, order, order.info.depositLiquidityParams.depositAmount);

        expectedSats = _computeAuctionSats(order.info.auction);
    }

    /**
     * @notice Releases bonded swap funds and returns the full bond to the corresponding market makers.
     * @dev This function processes an array of liquidity release requests. It first finalizes the underlying
     * liquidity releases by calling `releaseLiquidityBatch(paramsArray)`. Then, for each release request, it:
     *   - Retrieves the corresponding bonded swap using the order hash from the release parameters.
     *   - Verifies that a valid bonded swap exists (i.e. the market maker address is not zero).
     *   - Transfers the entire bond amount (in CB_BTC) back to the market maker.
     *   - Deletes the bonded swap record to prevent double releases.
     *
     * @param paramsArray An array of release liquidity parameters that includes an `orderHash` used to identify
     * the corresponding bonded swap record in `swapBonds`.
     *
     * @dev Reverts with:
     *   - `BondNotFoundOrAlreadyReleased()` if a bonded swap record is not found or has already been released.
     *   - `BondReleaseTransferFailed()` if the CB_BTC transfer to the market maker fails.
     */
    function releaseAndFree(Types.ReleaseLiquidityParams[] calldata paramsArray) external {
        // Call the underlying liquidity release function.
        // (Assumes that releaseLiquidityBatch processes all the deposit releases correctly.)
        releaseLiquidityBatch(paramsArray);

        uint256 i;
        uint256 paramsArrayLength = paramsArray.length;
        for (; i < paramsArrayLength; ) {
            Types.ReleaseLiquidityParams calldata param = paramsArray[i];
            // Retrieve the bonded swap record for this release request using
            // the order hash.
            Types.BondedSwap memory swapInfo = swapBonds[param.orderHash];
            // Ensure a valid bond is recorded.
            if (swapInfo.marketMaker == address(0)) revert Errors.BondNotFoundOrAlreadyReleased();

            // Release the full bond amount back to the market maker (no penalty applied here).
            bool success = CB_BTC.transfer(swapInfo.marketMaker, swapInfo.bond);
            if (!success) revert Errors.BondReleaseTransferFailed();

            // Clear the bond record to prevent double releasing.
            delete swapBonds[param.orderHash];

            unchecked {
                ++i;
            }
        }
    }

    // Withdraws liquidity for a deposit while applying a penalty based on SLASH_FEE_BIPS
    // A portion of the bond associated with this deposit is retained in the contract
    // as a penalty, tracked by updating `slashedBondFees` using `SLASH_FEE_BIPS`
    // The remaining bond amount is sent to the depositor's address
    /**
     * @notice Withdraws liquidity for a deposit while penalizing the market maker's bond.
     * @dev Applies a penalty based on SLASH_FEE_BIPS to the bond associated with the deposit.
     * A portion of the bond (the penalty) is retained by the contract and added to slashedBondFees;
     * the remaining bond amount is transferred to the depositor's address.
     *
     * The orderHash parameter is used to look up the corresponding bonded swap record.
     *
     * Requirements:
     * - A valid bonded swap must exist for the provided order hash.
     * - The CB_BTC transfer to MM must succeed.
     *
     * @param orderHash The unique identifier for the intent (used to look up the bonded swap record).
     * @dev Reverts with:
     *   - BondNotFoundOrAlreadyReleased() if no valid bond is found for the given order hash.
     *   - BondReleaseTransferFailed() if the CB_BTC transfer to the depositor fails.
     */
    function withdrawAndPenalize(bytes32 orderHash) external {
        // Retrieve the bonded swap record using the provided order hash.
        Types.BondedSwap memory swapInfo = swapBonds[orderHash];
        if (block.number < swapInfo.endBlock) revert Errors.AuctionNotEnded();
        if (swapInfo.marketMaker == address(0)) revert Errors.BondNotFoundOrAlreadyReleased();

        // Calculate the penalty based on SLASH_FEE_BIPS.
        // For example, if SLASH_FEE_BIPS is 500 (i.e. 5%), then penalty = 5% of the bond.
        uint96 penalty = (swapInfo.bond * SLASH_FEE_BIPS) / 10000;
        uint96 refundAmount = swapInfo.bond - penalty;

        // Update the global slashedBondFees by adding the penalty.
        slashedBondFees += penalty;

        // Transfer the remaining bond amount back to the MM.
        bool success = CB_BTC.transfer(swapInfo.marketMaker, refundAmount);
        if (!success) revert Errors.BondReleaseTransferFailed();

        // Clear the bonded swap record to prevent double withdrawals.
        delete swapBonds[orderHash];
    }

    // ---------------------------------------------------------------
    //                     INTERNAL FUNCTIONS
    // ---------------------------------------------------------------

    /**
     * @notice Validates and records a bond payment for an intent execution
     * @dev Checks the nonce, calculates the required bond amount based on the deposit size,
     *      transfers the bond from the market maker to the contract, and
     *      records the bonded swap in the swapBonds mapping.
     * @dev The bond amount is either a percentage of the deposit amount (BOND_BIPS/10000)
     *      or the minimum bond amount (MIN_BOND), whichever is greater.
     * @param order The signed intent containing deposit parameters
     * @custom:throws BondDepositTransferFailed If the bond transfer from msg.sender fails
     */
    function _validateBondAndRecord(Types.SignedIntent calldata order) internal {
        if (order.info.nonce != intentNonce[order.info.depositLiquidityParams.depositOwnerAddress]) {
            revert Errors.InvalidNonce();
        }

        uint96 requiredBond = _computeBond(order.info.depositLiquidityParams.depositAmount);

        // Do ERC20 transfer of bond amount from msg.sender to this contract
        bool success = CB_BTC.transferFrom(msg.sender, address(this), requiredBond);
        if (!success) {
            revert Errors.BondDepositTransferFailed();
        }

        // Record the bonded swap.
        bytes32 orderId = order.orderHash; // Alternatively, compute a unique identifier.
        swapBonds[orderId] = Types.BondedSwap({
            marketMaker: msg.sender,
            bond: requiredBond,
            endBlock: order.info.auction.endBlock
        });
    }

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
        uint256 preCallcbBTC = CB_BTC.balanceOf(address(this));

        // Step 6: Give approval to callback contract for ERC20
        IERC20(order.info.tokenIn).approve(address(route.router), depositAmount);

        // Step 7: Call solver provided router with routeCalldata
        (bool success, ) = route.router.call(route.routeData);
        if (!success) {
            revert Errors.RouterCallFailed();
        }

        // Step 8: Validate sufficient cbBTC was sent
        uint256 postCallcbBTC = CB_BTC.balanceOf(address(this));
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
