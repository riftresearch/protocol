// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {console} from "forge-std/src/console.sol";
import {ISP1Verifier} from "sp1-contracts/contracts/src/ISP1Verifier.sol";
import {IERC20} from "@openzeppelin-contracts/interfaces/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin-contracts/interfaces/IERC20Metadata.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

import {Constants} from "./libraries/Constants.sol";
import {Errors} from "./libraries/Errors.sol";
import {Types} from "./libraries/Types.sol";
import {Events} from "./libraries/Events.sol";
import {VaultLib} from "./libraries/VaultLib.sol";
import {RiftUtils} from "./libraries/RiftUtils.sol";
import {BitcoinLightClient} from "./BitcoinLightClient.sol";

/**
 * @title RiftExchange
 * @author alpinevm <https://github.com/alpinevm>
 * @author spacegod <https://github.com/bruidbarrett>
 * @notice A decentralized exchange for cross-chain Bitcoin to ERC20 swaps
 * @dev Uses a Bitcoin light client and zero-knowledge proofs for verification of payment
 */
contract RiftExchange is BitcoinLightClient {
    // -----------------------------------------------------------------------
    //                                IMMUTABLES
    // -----------------------------------------------------------------------
    IERC20 public immutable DEPOSIT_TOKEN;
    uint8 public immutable TOKEN_DECIMALS;
    bytes32 public immutable CIRCUIT_VERIFICATION_KEY;
    ISP1Verifier public immutable VERIFIER;
    address public immutable FEE_ROUTER_ADDRESS;

    // -----------------------------------------------------------------------
    //                                 STATE
    // -----------------------------------------------------------------------
    bytes32[] public vaultCommitments;
    bytes32[] public swapCommitments;
    uint256 public accumulatedFeeBalance;

    // -----------------------------------------------------------------------
    //                              CONSTRUCTOR
    // -----------------------------------------------------------------------
    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter
    ) BitcoinLightClient(_mmrRoot) {
        DEPOSIT_TOKEN = IERC20(_depositToken);
        TOKEN_DECIMALS = IERC20Metadata(_depositToken).decimals();
        CIRCUIT_VERIFICATION_KEY = _circuitVerificationKey;
        VERIFIER = ISP1Verifier(_verifier);
        FEE_ROUTER_ADDRESS = _feeRouter;
    }

    // -----------------------------------------------------------------------
    //                             EXTERNAL FUNCTIONS
    // -----------------------------------------------------------------------

    /// @notice Sends accumulated protocol fees to the fee router contract
    /// @dev Reverts if there are no fees to pay or if the transfer fails
    function payoutToFeeRouter() external {
        uint256 feeBalance = accumulatedFeeBalance;
        if (feeBalance == 0) revert Errors.NoFeeToPay();
        accumulatedFeeBalance = 0;
        if (!DEPOSIT_TOKEN.transfer(FEE_ROUTER_ADDRESS, feeBalance)) revert Errors.TransferFailed();
    }

    /// @notice Deposits new liquidity into a new vault
    function depositLiquidity(Types.DepositLiquidityParams calldata params) external {
        // Determine vault index
        uint256 vaultIndex = vaultCommitments.length;

        // Create deposit liquidity request
        (Types.DepositVault memory vault, bytes32 depositHash) = _prepareDeposit(params, vaultIndex);

        // Add deposit hash to vault commitments
        vaultCommitments.push(depositHash);

        // Finalize deposit
        _finalizeDeposit(vault);
    }

    /// @notice Deposits new liquidity by overwriting an existing empty vault
    function depositLiquidityWithOverwrite(Types.DepositLiquidityWithOverwriteParams calldata params) external {
        // Create deposit liquidity request
        uint256 vaultIndex = params.overwriteVault.vaultIndex;
        (Types.DepositVault memory vault, bytes32 depositHash) = _prepareDeposit(params.depositParams, vaultIndex);

        // Ensure passed vault is real and overwritable
        VaultLib.validateDepositVaultCommitment(params.overwriteVault, vaultCommitments);
        if (params.overwriteVault.depositAmount != 0) revert Errors.DepositVaultNotOverwritable();

        // Overwrite deposit vault
        vaultCommitments[vaultIndex] = depositHash;

        // Finalize deposit
        _finalizeDeposit(vault);
    }

    /// @notice Withdraws liquidity from a deposit vault after the lockup period
    /// @dev Anyone can call, reverts if vault doesn't exist, is empty, or still in lockup period
    function withdrawLiquidity(Types.DepositVault calldata vault) external {
        VaultLib.validateDepositVaultCommitment(vault, vaultCommitments);
        if (vault.depositAmount == 0) revert Errors.EmptyDepositVault();
        // TODO: lock up period needs to be a function how many confirmation blocks the deposit is locked for
        // TODO: should be possible to create a deposit vault on behalf of another address
        if (block.timestamp < vault.depositTimestamp + Constants.DEPOSIT_LOCKUP_PERIOD) {
            revert Errors.DepositStillLocked();
        }

        Types.DepositVault memory updatedVault = vault;
        updatedVault.depositAmount = 0;
        updatedVault.depositFee = 0;

        vaultCommitments[vault.vaultIndex] = VaultLib.hashDepositVault(updatedVault);

        if (!DEPOSIT_TOKEN.transfer(vault.ownerAddress, vault.depositAmount)) revert Errors.TransferFailed();

        emit Events.VaultUpdated(updatedVault, Types.VaultUpdateContext.Withdraw);
    }

    /// @notice Submits a a batch of swap proofs and adds them to swapCommitments or overwrites an existing completed swap commitment
    function submitBatchSwapProof(
        Types.SubmitSwapProofParams[] calldata swapParams,
        Types.BlockProofParams calldata blockProofParams,
        Types.ProposedSwap[] calldata overwriteSwaps,
        bytes calldata proof
    ) external {
        (Types.ProposedSwap[] memory swaps, bytes32[] memory updatedSwapHashes) = _validateSwaps(
            swapParams,
            blockProofParams,
            overwriteSwaps,
            proof
        );

        for (uint256 i = 0; i < swaps.length; i++) {
            swapCommitments.push(updatedSwapHashes[i]);
        }
        emit Events.SwapsUpdated(swaps, Types.SwapUpdateContext.Created);
    }

    /// @notice Releases locked liquidity to the swap taker after the challenge period
    function releaseLiquidity(Types.ReleaseLiquidityParams calldata params) external {
        // TODO: Batch releases like submitBatchSwapProof
        VaultLib.validateSwapCommitment(params.swap, swapCommitments);
        if (params.swap.state != Types.SwapState.Proved) revert Errors.SwapNotProved();
        if (block.timestamp < params.swap.liquidityUnlockTimestamp) revert Errors.StillInChallengePeriod();

        Types.BlockLeaf memory swapBlockLeaf = Types.BlockLeaf({
            blockHash: params.swap.swapBitcoinBlockHash,
            height: params.swapBlockHeight,
            cumulativeChainwork: params.swapBlockChainwork
        });
        if (
            !_proveBlockInclusion(
                swapBlockLeaf,
                params.bitcoinSwapBlockSiblings,
                params.bitcoinSwapBlockPeaks,
                params.tipBlockHeight
            )
        ) {
            revert Errors.InvalidSwapBlockInclusionProof();
        }

        if (
            !_proveBlockInclusion(
                params.bitcoinConfirmationBlockLeaf,
                params.bitcoinConfirmationBlockSiblings,
                params.bitcoinConfirmationBlockPeaks,
                params.tipBlockHeight
            )
        ) {
            revert Errors.InvalidConfirmationBlockInclusionProof();
        }

        if (params.bitcoinConfirmationBlockLeaf.height != params.swapBlockHeight + params.swap.confirmationBlocks) {
            revert Errors.InvalidConfirmationBlockDelta();
        }

        bytes32 depositVaultCommitment = VaultLib.validateDepositVaultCommitment(
            params.utilizedVault,
            vaultCommitments
        );
        if (depositVaultCommitment != params.swap.depositVaultCommitment) {
            revert Errors.InvalidVaultCommitment();
        }

        Types.DepositVault memory updatedVault = params.utilizedVault;
        updatedVault.depositAmount = 0;
        updatedVault.depositFee = 0;

        vaultCommitments[updatedVault.vaultIndex] = VaultLib.hashDepositVault(updatedVault);
        emit Events.VaultUpdated(updatedVault, Types.VaultUpdateContext.Release);

        Types.ProposedSwap memory updatedSwap = params.swap;
        updatedSwap.state = Types.SwapState.Finalized;
        swapCommitments[params.swap.swapIndex] = VaultLib.hashSwap(updatedSwap);

        accumulatedFeeBalance += params.swap.totalSwapFee;

        Types.ProposedSwap[] memory updatedSwaps = new Types.ProposedSwap[](1);
        updatedSwaps[0] = updatedSwap;

        emit Events.SwapsUpdated(updatedSwaps, Types.SwapUpdateContext.Complete);

        if (!DEPOSIT_TOKEN.transfer(params.swap.specifiedPayoutAddress, params.swap.totalSwapOutput)) {
            revert Errors.TransferFailed();
        }
    }

    // -----------------------------------------------------------------------
    //                            INTERNAL FUNCTIONS
    // -----------------------------------------------------------------------

    /// @notice Internal function to prepare and validate a new deposit
    function _prepareDeposit(
        Types.DepositLiquidityParams calldata params,
        uint256 depositVaultIndex
    ) internal view returns (Types.DepositVault memory, bytes32) {
        if (params.depositAmount < Constants.MIN_DEPOSIT_AMOUNT) revert Errors.DepositAmountTooLow();
        if (params.expectedSats < Constants.MIN_OUTPUT_SATS) revert Errors.SatOutputTooLow();
        if (!VaultLib.validateP2WPKHScriptPubKey(params.btcPayoutScriptPubKey)) revert Errors.InvalidScriptPubKey();

        if (!_proveBlockInclusionAtTip(params.tipBlockLeaf, params.tipBlockSiblings, params.tipBlockPeaks)) {
            revert Errors.InvalidTipBlockInclusionProof();
        }

        uint256 depositFee = RiftUtils.calculateFeeFromInitialDeposit(params.depositAmount);

        Types.DepositVault memory vault = Types.DepositVault({
            vaultIndex: depositVaultIndex,
            depositTimestamp: uint64(block.timestamp),
            depositAmount: params.depositAmount - depositFee,
            depositFee: depositFee,
            expectedSats: params.expectedSats,
            btcPayoutScriptPubKey: params.btcPayoutScriptPubKey,
            specifiedPayoutAddress: params.specifiedPayoutAddress,
            ownerAddress: params.depositOwnerAddress,
            salt: EfficientHashLib.hash(
                params.depositSalt,
                bytes32(depositVaultIndex),
                bytes32(uint256(block.chainid))
            ),
            confirmationBlocks: params.confirmationBlocks,
            attestedBitcoinBlockHeight: params.tipBlockLeaf.height
        });

        return (vault, VaultLib.hashDepositVault(vault));
    }

    // TODO: add function to do pure block updates

    /// @notice Internal function to finalize a deposit
    function _finalizeDeposit(Types.DepositVault memory vault) internal {
        emit Events.VaultUpdated(vault, Types.VaultUpdateContext.Created);
        if (!DEPOSIT_TOKEN.transferFrom(msg.sender, address(this), vault.depositAmount + vault.depositFee)) {
            revert Errors.TransferFailed();
        }
    }

    /// @notice Internal function to prepare and validate a batch of swap proofs
    function _validateSwaps(
        Types.SubmitSwapProofParams[] calldata swapParams,
        Types.BlockProofParams calldata blockProofParams,
        Types.ProposedSwap[] calldata overwriteSwaps,
        bytes calldata proof
    ) internal returns (Types.ProposedSwap[] memory swaps, bytes32[] memory updatedSwapHashes) {
        // if (swapParams.length == 0) revert Errors.NoSwapsToSubmit();
        // TODO: explicit check for uint16 overflow on max swaps?
        Types.SwapPublicInput[] memory swapPublicInputs = new Types.SwapPublicInput[](swapParams.length);
        swaps = new Types.ProposedSwap[](swapParams.length);
        updatedSwapHashes = new bytes32[](swapParams.length);

        uint256 swapIndexPointer = swapCommitments.length;
        for (uint256 i = 0; i < swapParams.length; i++) {
            uint256 swapIndex = swapIndexPointer; // default is append
            Types.SubmitSwapProofParams calldata params = swapParams[i];
            if (params.storageStrategy == Types.StorageStrategy.Append) {
                swapIndexPointer++;
            } else if (params.storageStrategy == Types.StorageStrategy.Overwrite) {
                VaultLib.validateSwapCommitment(overwriteSwaps[params.localOverwriteIndex], swapCommitments);
                if (overwriteSwaps[params.localOverwriteIndex].state != Types.SwapState.Finalized) {
                    revert Errors.CannotOverwriteOngoingSwap();
                }
                swapIndex = overwriteSwaps[params.localOverwriteIndex].swapIndex;
            }

            (uint256 totalSwapOutput, uint256 totalSwapFee) = VaultLib.calculateSwapTotals(params.vault);
            bytes32 depositVaultCommitment = VaultLib.validateDepositVaultCommitment(params.vault, vaultCommitments);

            swapPublicInputs[i] = Types.SwapPublicInput({
                swapBitcoinBlockHash: params.swapBitcoinBlockHash,
                swapBitcoinTxid: params.swapBitcoinTxid,
                depositVaultCommitment: depositVaultCommitment
            });

            swaps[i] = Types.ProposedSwap({
                swapIndex: swapIndex,
                swapBitcoinBlockHash: params.swapBitcoinBlockHash,
                confirmationBlocks: params.vault.confirmationBlocks,
                liquidityUnlockTimestamp: uint64(
                    block.timestamp +
                        RiftUtils.calculateChallengePeriod(
                            // The challenge period is based on the worst case reorg which would be to the
                            // depositors originally attested bitcoin block height
                            blockProofParams.tipBlockLeaf.height - params.vault.attestedBitcoinBlockHeight
                        )
                ),
                specifiedPayoutAddress: params.vault.specifiedPayoutAddress,
                totalSwapFee: totalSwapFee,
                totalSwapOutput: totalSwapOutput,
                state: Types.SwapState.Proved,
                depositVaultCommitment: depositVaultCommitment
            });

            updatedSwapHashes[i] = VaultLib.hashSwap(swaps[i]);
        }

        bytes32 compressedLeavesCommitment = EfficientHashLib.hash(blockProofParams.compressedBlockLeaves);

        VERIFIER.verifyProof(
            CIRCUIT_VERIFICATION_KEY,
            abi.encode(
                Types.ProofPublicInput({
                    proofType: Types.ProofType.Combined,
                    swaps: swapPublicInputs,
                    lightClient: Types.LightClientPublicInput({
                        previousMmrRoot: blockProofParams.priorMmrRoot,
                        newMmrRoot: blockProofParams.newMmrRoot,
                        compressedLeavesCommitment: compressedLeavesCommitment
                    })
                })
            ),
            proof
        );

        _updateRoot(blockProofParams.priorMmrRoot, blockProofParams.newMmrRoot, blockProofParams.compressedBlockLeaves);
        // TODO: someone could submit swap proof, locking in some given attested bitcoin block height, but then submit a large number of
        // of blocks right after, affectively ddosing the light client. Make it impossible to submit a
        // a block update that overwrites the previous fradulent. ~ reason about the exact conditions under which this could happen ~

        // TODO: This isn't ideal, this check requires _updateRoot to always succeed at updating to the new root which shouldn't
        // be a requirement for swap inclusion proofs to succeed (in the case someone updates the root mid proof gen -> that shouldn't
        // cause down stream proof verification to fail).
        // - Could store the current latest block height in the contract and use that value as the basis for their attested bitcoin block height [simplest]
        if (
            !_proveBlockInclusionAtTip(
                blockProofParams.tipBlockLeaf,
                blockProofParams.tipBlockSiblings,
                blockProofParams.tipBlockPeaks
            )
        ) {
            revert Errors.InvalidTipBlockInclusionProof();
        }
    }

    // -----------------------------------------------------------------------
    //                              READ FUNCTIONS
    // -----------------------------------------------------------------------

    function getVaultCommitmentsLength() external view returns (uint256) {
        return vaultCommitments.length;
    }

    function getSwapCommitmentsLength() external view returns (uint256) {
        return swapCommitments.length;
    }

    function getVaultCommitment(uint256 vaultIndex) external view returns (bytes32) {
        return vaultCommitments[vaultIndex];
    }

    function getSwapCommitment(uint256 swapIndex) external view returns (bytes32) {
        return swapCommitments[swapIndex];
    }
}
