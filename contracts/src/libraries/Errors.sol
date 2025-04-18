// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

library Errors {
    // --------- LIGHT CLIENT --------- //
    error BlockNotInChain();
    error BlockNotConfirmed();
    error ChainworkTooLow();
    error CheckpointNotEstablished();

    // --------- RIFT EXCHANGE --------- //
    error InvalidDepositTokenDecimals();
    error DepositAmountTooLow();
    error SatOutputTooLow();
    error DepositVaultNotOverwritable();
    error InvalidScriptPubKey();
    error DepositVaultDoesNotExist();
    error SwapDoesNotExist();
    error EmptyDepositVault();
    error DepositStillLocked();
    error CannotOverwriteOngoingSwap();
    error NoFeeToPay();
    error InvalidVaultHash(bytes32 actual, bytes32 expected);
    error StillInChallengePeriod();
    error SwapNotProved();
    error NotEnoughConfirmationBlocks();
    error NoSwapsToSubmit();

    // --- BTC DUTCH AUCTION HOUSE --- //
    error DutchAuctionDoesNotExist();
    error InvalidTickSize();
    error AuctionExpired();
    error AuctionAlreadyFilled();
    error AuctionAlreadyWithdrawn();
    error AuctionNotExpired();
}
