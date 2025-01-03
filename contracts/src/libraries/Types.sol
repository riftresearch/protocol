// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

library Types {
    // --------- LIGHT CLIENT TYPES --------- //
    struct BlockLeaf {
        bytes32 blockHash;
        uint64 height;
        uint256 cumulativeChainwork;
    }

    // --------- EXCHANGE SETTLEMENT TYPES --------- //
    enum SwapState {
        None,
        Proved,
        Completed
    }

    struct DepositVault {
        uint256 vaultIndex;
        uint64 depositTimestamp;
        // this is the amount of capital actually available to be swapped
        uint256 depositAmount;
        // this is the fee the maker will pay
        uint256 depositFee;
        // this is the amount of BTC the maker will need to receive
        // for their liquidity to be unlocked.
        // expectedSats / depositAmount = BTC/USD exchange rate set by the maker
        uint64 expectedSats;
        // this is the bitcoin script for the maker to receive their BTC
        bytes22 btcPayoutScriptPubKey;
        address specifiedPayoutAddress;
        address ownerAddress;
        bytes32 nonce;
        uint8 confirmationBlocks;
        uint64 attestedBitcoinBlockHeight;
    }

    struct ProposedSwap {
        uint256 swapIndex;
        bytes32 aggregateVaultCommitment;
        bytes32 swapBitcoinBlockHash;
        // number of Bitcoin block confirmations required after the swap transaction
        // (e.g., 1 = only the block containing the swap, 2 = swap block + 1 confirmation, etc.)
        uint8 confirmationBlocks;
        uint64 liquidityUnlockTimestamp;
        address specifiedPayoutAddress;
        //  this is the total fee for the swap including the deposit fee of each maker
        uint256 totalSwapFee;
        // this is the total amount of output ERC20 tokens the taker will receive
        uint256 totalSwapOutput;
        SwapState state;
    }

    struct SwapProofPublicInputs {
        // rift swap verification
        uint8 confirmationBlocks;
        bytes32 swapBitcoinBlockHash;
        bytes32 swapBitcoinTxid; // not strictly necessary to be public, but useful for tracking the swap
        bytes32 aggregateVaultCommitment;
        address specifiedPayoutAddress;
        uint256 totalSwapFee;
        uint256 totalSwapOutput;
        // bitcoin light client verification
        bytes32 previousMmrRoot;
        bytes32 newMmrRoot;
        bytes32 compressedLeavesCommitment;
    }
}
