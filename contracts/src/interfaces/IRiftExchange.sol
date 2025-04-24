// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {IBitcoinLightClient, BlockLeaf, BitcoinCheckpoint} from "./IBitcoinLightClient.sol";

// -----------------------------------------------------------------------
//                              ENUMS & STRUCTS
// -----------------------------------------------------------------------

enum SwapState {
    Pending,
    Proved,
    Finalized
}

struct DepositVault {
    uint256 vaultIndex;
    uint64 depositTimestamp;
    uint64 depositUnlockTimestamp;
    uint256 vaultAmount;
    uint256 takerFee;
    uint64 expectedSats;
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
    uint8 confirmationBlocks;
    uint64 liquidityUnlockTimestamp;
    address specifiedPayoutAddress;
    uint256 totalSwapOutput;
    uint256 takerFee;
    SwapState state;
}

enum ProofType {
    SwapOnly,
    LightClientOnly,
    Combined
}

struct SwapPublicInput {
    bytes32 swapBitcoinTxid;
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
    SwapPublicInput[] swaps;
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

struct BaseDepositLiquidityParams {
    address depositOwnerAddress;
    bytes25 btcPayoutScriptPubKey;
    bytes32 depositSalt;
    uint8 confirmationBlocks;
    BlockLeaf safeBlockLeaf;
}

struct DepositLiquidityParams {
    BaseDepositLiquidityParams base;
    address specifiedPayoutAddress;
    uint256 depositAmount;
    uint64 expectedSats;
    bytes32[] safeBlockSiblings;
    bytes32[] safeBlockPeaks;
}

struct BlockProofParams {
    bytes32 priorMmrRoot;
    bytes32 newMmrRoot;
    bytes compressedBlockLeaves;
    BlockLeaf tipBlockLeaf;
}

struct SubmitSwapProofParams {
    bytes32 swapBitcoinTxid;
    DepositVault vault;
    BlockLeaf swapBitcoinBlockLeaf;
    bytes32[] swapBitcoinBlockSiblings;
    bytes32[] swapBitcoinBlockPeaks;
}

struct ReleaseLiquidityParams {
    ProposedSwap swap;
    bytes32[] bitcoinSwapBlockSiblings;
    bytes32[] bitcoinSwapBlockPeaks;
    DepositVault utilizedVault;
    uint32 tipBlockHeight;
}


// -----------------------------------------------------------------------
//                                INTERFACE
// -----------------------------------------------------------------------

/// @title IRiftExchange
/// @notice Interface for the RiftExchange contract.
interface IRiftExchange is IBitcoinLightClient {
    // --- Errors ---

    error InvalidDepositTokenDecimals(uint8 actual, uint8 expected);
    error DepositAmountTooLow();
    error SatOutputTooLow();
    error InvalidScriptPubKey();
    error EmptyDepositVault();
    error DepositStillLocked();
    error NoFeeToPay();
    error InvalidVaultHash(bytes32 actual, bytes32 expected);
    error StillInChallengePeriod();
    error SwapNotProved();
    error NotEnoughConfirmationBlocks();
    error NoSwapsToSubmit();

    // --- Events ---

    event VaultsUpdated(DepositVault[] vaults, VaultUpdateContext context);
    event SwapsUpdated(ProposedSwap[] swaps, SwapUpdateContext context);


    // --- Constants / Immutables ---
    function MIN_OUTPUT_SATS() external pure returns (uint16);
    function MIN_CONFIRMATION_BLOCKS() external pure returns (uint8);
    function ERC20_BTC() external view returns (address);
    function CIRCUIT_VERIFICATION_KEY() external view returns (bytes32);
    function VERIFIER() external view returns (address);

    // --- State Variables ---
    function vaultHashes(uint256 vaultIndex) external view returns (bytes32);
    function swapHashes(uint256 swapIndex) external view returns (bytes32);
    function accumulatedFeeBalance() external view returns (uint256);
    function feeRouterAddress() external view returns (address);
    function takerFeeBips() external view returns (uint16);

    // --- External Functions ---
    function payoutToFeeRouter() external;
    function adminSetFeeRouterAddress(address _feeRouter) external;
    function adminSetTakerFeeBips(uint16 _takerFeeBips) external;
    function withdrawLiquidity(DepositVault calldata vault) external;
    function submitBatchSwapProofWithLightClientUpdate(
        SubmitSwapProofParams[] calldata swapParams,
        BlockProofParams calldata blockProofParams,
        bytes calldata proof
    ) external;
    function submitBatchSwapProof(
        SubmitSwapProofParams[] calldata swapParams,
        bytes calldata proof
    ) external;
    function releaseLiquidityBatch(ReleaseLiquidityParams[] calldata paramsArray) external;
    function updateLightClient(BlockProofParams calldata blockProofParams, bytes calldata proof) external;

    // --- Read Functions ---
    function getVaultHashesLength() external view returns (uint256);
    function getSwapHashesLength() external view returns (uint256);
    function verifyZkProof(ProofPublicInput memory proofPublicInput, bytes calldata proof) external view;
    // TODO: Do we need this? This exists b/c we need the type in circuits
    function serializeLightClientPublicInput(LightClientPublicInput memory input) external pure returns (bytes memory);
} 