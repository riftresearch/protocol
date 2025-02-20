// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

library Errors {
    // --------- LIGHT CLIENT ERRORS --------- //
    error InvalidLeavesCommitment();

    // --------- EXCHANGE SETTLEMENT ERRORS --------- //
    error TransferFailed();
    error NewDepositsPaused();
    error DepositAmountTooLow();
    error SatOutputTooLow();
    error DepositVaultNotOverwritable();
    error InvalidScriptPubKey();
    error DepositVaultDoesNotExist();
    error SwapDoesNotExist();
    error EmptyDepositVault();
    error DepositStillLocked();
    error InvalidSwapBlockInclusionProof();
    error InvalidConfirmationBlockInclusionProof();
    error CannotOverwriteOngoingSwap();
    error NoFeeToPay();
    error InvalidVaultCommitment();
    error StillInChallengePeriod();
    error SwapNotProved();
    error InvalidConfirmationBlockDelta();
    error NotEnoughConfirmationBlocks();
    error NoVaults();
    error PayoutAddressMismatch();
    error InvalidSwapTotals();
    error InvalidBlockInclusionProof();
    error RootWasNotUpdated();
    error CheckpointNotEstablished();
    error ChainworkTooLow();
    error NoSwapsToSubmit();
    error NotEnoughConfirmations();
}
