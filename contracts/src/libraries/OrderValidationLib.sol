// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {CreateOrderParams} from "../interfaces/IRiftExchange.sol";
import {FeeLib} from "./FeeLib.sol";
import {BitcoinScriptLib} from "./BitcoinScriptLib.sol";

library OrderValidationLib {
    /// @notice The minimum amount of expectedSats for an Order
    /// @dev This prevents dust errors on btc side
    uint16 constant MIN_OUTPUT_SATS = 1000;
    /// @notice The minimum threshold for the number of confirmations 
    /// @dev Decreases the likelihood a proof will actually have to be challenged
    /// under normal operations.
    uint8 constant MIN_CONFIRMATION_BLOCKS = 2;

    error DepositAmountTooLow();
    error SatOutputTooLow();
    error NotEnoughConfirmationBlocks();
    error InvalidScriptPubKey();

    function validate(CreateOrderParams memory params, uint16 _takerFeeBips) internal pure {
        if (params.depositAmount < FeeLib.calculateMinDepositAmount(_takerFeeBips)) revert DepositAmountTooLow();
        if (params.expectedSats < MIN_OUTPUT_SATS) revert SatOutputTooLow();
        if (params.base.confirmationBlocks < MIN_CONFIRMATION_BLOCKS) revert NotEnoughConfirmationBlocks();
        if (!BitcoinScriptLib.validateScriptPubKey(params.base.bitcoinScriptPubKey))
            revert InvalidScriptPubKey();
    }
}