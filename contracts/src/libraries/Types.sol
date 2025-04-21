// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

library Types {
    // --------- LIGHT CLIENT TYPES --------- //
    struct BlockLeaf {
        bytes32 blockHash;
        uint32 height;
        uint256 cumulativeChainwork;
    }

    // --------- EXCHANGE SETTLEMENT TYPES --------- //
    enum SwapState {
        Pending,
        Proved,
        Finalized
    }

    struct DepositVault {
        uint256 vaultIndex;
        uint64 depositTimestamp;
        uint64 depositUnlockTimestamp;
        // The amount of tokens the maker will receive after successful settlement
        uint256 vaultAmount;
        // the fee the taker pays the protocol
        uint256 takerFee;
        // this is the amount of BTC the maker will need to receive
        // for their liquidity to be unlocked.
        // expectedSats / depositAmount = BTC/USD exchange rate set by the maker
        uint64 expectedSats;
        // this is the bitcoin script for the maker to receive their BTC
        bytes25 btcPayoutScriptPubKey;
        address specifiedPayoutAddress;
        address ownerAddress;
        bytes32 salt;
        uint8 confirmationBlocks;
        uint64 attestedBitcoinBlockHeight;
    }

    struct ProposedSwap {
        uint256 swapIndex;
        bytes32 depositVaultHash;
        BlockLeaf swapBitcoinBlockLeaf;
        // number of Bitcoin block confirmations required after the swap transaction
        // (e.g., 1 = only the block containing the swap, 2 = swap block + 1 confirmation, etc.)
        uint8 confirmationBlocks;
        uint64 liquidityUnlockTimestamp;
        address specifiedPayoutAddress;
        // this is the total amount of output ERC20 tokens the taker will receive
        uint256 totalSwapOutput;
        // this is the fee the taker pays the protocol
        uint256 takerFee;
        SwapState state;
    }

    enum ProofType {
        SwapOnly,
        LightClientOnly,
        Combined
    }

    struct SwapPublicInput {
        bytes32 swapBitcoinTxid; // not strictly necessary to be public, but useful for tracking the swap
        bytes32 swapBitcoinBlockHash;
        bytes32 depositVaultHash;
    }

    struct LightClientPublicInput {
        bytes32 previousMmrRoot;
        bytes32 newMmrRoot;
        bytes32 compressedLeavesHash;
        BlockLeaf tipBlockLeaf;
    }

    struct ProofPublicInput {
        ProofType proofType;
        // rift swap verification
        SwapPublicInput[] swaps;
        // bitcoin light client verification
        LightClientPublicInput lightClient;
    }

    enum VaultUpdateContext {
        Created,
        Withdraw,
        Release
    }

    enum SwapUpdateContext {
        Created,
        Complete
    }

    struct MMRProof {
        BlockLeaf blockLeaf;
        bytes32[] siblings;
        bytes32[] peaks;
        uint32 leafCount;
        bytes32 mmrRoot;
    }

    struct ReleaseMMRProof {
        MMRProof proof;
        MMRProof tipProof;
    }

    struct DeploymentParams {
        BlockLeaf tipBlockLeaf;
        bytes32 mmrRoot;
        bytes32 circuitVerificationKey;
    }

    // -----------------------------------------------------------------------
    //                             PARAMETER STRUCTS
    // -----------------------------------------------------------------------
    /**
     * @param depositOwnerAddress Address to receive swap proceeds
     * @param btcPayoutScriptPubKey Bitcoin script for receiving BTC
     * @param depositSalt User generated salt for vault nonce
     * @param confirmationBlocks Number of Bitcoin blocks required for confirmation
     * @param safeBlockLeaf The leaf representing a block the depositor believes is highly unlikely to be reorged out of the chain
     */
    struct BaseDepositLiquidityParams {
        address depositOwnerAddress;
        bytes25 btcPayoutScriptPubKey;
        bytes32 depositSalt;
        uint8 confirmationBlocks;
        Types.BlockLeaf safeBlockLeaf;
    }

    /**
     * @param base Base depositLiquidity parameters
     * @param specifiedPayoutAddress Address to receive swap proceeds
     * @param depositAmount Amount of ERC20 tokens to deposit including fee
     * @param expectedSats Expected BTC output in satoshis
     * @param safeBlockSiblings Merkle proof siblings for safe block inclusion
     * @param safeBlockPeaks MMR peaks for safe block inclusion
     */
    struct DepositLiquidityParams {
        BaseDepositLiquidityParams base;
        address specifiedPayoutAddress;
        uint256 depositAmount;
        uint64 expectedSats;
        bytes32[] safeBlockSiblings;
        bytes32[] safeBlockPeaks;
    }

     /**
     * @param priorMmrRoot Previous MMR root used to generate this swap proof
     * @param newMmrRoot Updated MMR root at least incluing up to the confirmation block
     * @param compressedBlockLeaves Compressed block data for MMR Data Availability
     * @param tipBlockLeaf The leaf node representing the current tip block
     * @param tipBlockSiblings Merkle proof siblings for tip block inclusion
     * @param tipBlockPeaks MMR peaks for tip block inclusion
     */
    struct BlockProofParams {
        bytes32 priorMmrRoot;
        bytes32 newMmrRoot;
        bytes compressedBlockLeaves;
        Types.BlockLeaf tipBlockLeaf;
    }

    /**
     * @notice Struct for submitSwapProof parameters
     *
     * @param swapBitcoinTxid Txid of the Bitcoin transaction containing the swap
     * @param vault Deposit vault being used in the swap
     * @param swapBitcoinBlockLeaf The leaf node for the swap block in the MMR
     * @param swapBitcoinBlockSiblings Merkle proof siblings for the swap block
     * @param swapBitcoinBlockPeaks MMR peaks for the swap block
     */
    struct SubmitSwapProofParams {
        bytes32 swapBitcoinTxid;
        Types.DepositVault vault;
        Types.BlockLeaf swapBitcoinBlockLeaf;
        bytes32[] swapBitcoinBlockSiblings;
        bytes32[] swapBitcoinBlockPeaks;
    }

    /**
     * @notice Struct for releaseLiquidity parameters
     *
     * @param swap Proposed swap data
     * @param swapBlockChainwork The cumulative chainwork of the swap's block
     * @param swapBlockHeight The block height of the swap
     * @param bitcoinSwapBlockSiblings Merkle proof siblings for the swap block
     * @param bitcoinSwapBlockPeaks MMR peaks for the swap block
     * @param bitcoinConfirmationBlockLeaf The leaf node for the confirmation block
     * @param bitcoinConfirmationBlockSiblings Merkle proof siblings for the confirmation block
     * @param bitcoinConfirmationBlockPeaks MMR peaks for the confirmation block
     * @param utilizedVault Deposit vault used in the swap
     * @param tipBlockHeight The height of the current tip block
     */
    struct ReleaseLiquidityParams {
        Types.ProposedSwap swap;
        bytes32[] bitcoinSwapBlockSiblings;
        bytes32[] bitcoinSwapBlockPeaks;
        Types.DepositVault utilizedVault;
        uint32 tipBlockHeight;
    }

    struct BitcoinCheckpoint {
        bool established;
        Types.BlockLeaf tipBlockLeaf;
    }



    /// AUCTION STATE
    enum DutchAuctionState {
        Created,
        Filled,
        Withdrawn
    }

    struct DutchAuction {
        uint256 auctionIndex;
        Types.BaseDepositLiquidityParams baseDepositParams;
        Types.DutchAuctionParams dutchAuctionParams;
        uint256 depositAmount;
        uint256 startBlock;
        uint64 startTimestamp;
        DutchAuctionState state;
    }

    struct DutchAuctionParams {
        uint64 startBtcOut; // the starting price of the auction
        uint64 tickSize; // the amount the price will decrease each tick
        uint64 ticks; // the number of ticks (blocks) in the auction
        uint64 deadline; // the deadline of the auction (as a timestamp)
    }


}
