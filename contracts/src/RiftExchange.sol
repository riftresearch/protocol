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
 * @notice A decentralized exchange for cross-chain Bitcoin<>ERC20 swaps
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
        address _feeRouter,
        Types.BlockLeaf memory _tipBlockLeaf
    ) BitcoinLightClient(_mmrRoot, _tipBlockLeaf) {
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
        if (
            block.timestamp < vault.depositTimestamp + RiftUtils.calculateDepositLockupPeriod(vault.confirmationBlocks)
        ) {
            revert Errors.DepositStillLocked();
        }

        Types.DepositVault memory updatedVault = vault;
        updatedVault.depositAmount = 0;
        updatedVault.depositFee = 0;

        vaultCommitments[updatedVault.vaultIndex] = VaultLib.hashDepositVault(updatedVault);

        if (!DEPOSIT_TOKEN.transfer(vault.ownerAddress, vault.depositAmount)) revert Errors.TransferFailed();

        Types.DepositVault[] memory updatedVaults = new Types.DepositVault[](1);
        updatedVaults[0] = updatedVault;
        emit Events.VaultsUpdated(updatedVaults, Types.VaultUpdateContext.Withdraw);
    }

    /// @notice Submits a a batch of swap proofs and adds them to swapCommitments or overwrites an existing completed swap commitment
    function submitBatchSwapProofWithLightClientUpdate(
        Types.SubmitSwapProofParams[] calldata swapParams,
        Types.BlockProofParams calldata blockProofParams,
        Types.ProposedSwap[] calldata overwriteSwaps,
        bytes calldata proof
    ) external {
        // optimistically update root, needed b/c we validate current inclusion in the chain for each swap
        _updateRoot(
            blockProofParams.priorMmrRoot,
            blockProofParams.newMmrRoot,
            blockProofParams.tipBlockLeaf,
            blockProofParams.compressedBlockLeaves
        );

        uint32 currentLightClientHeight = blockProofParams.tipBlockLeaf.height;

        (Types.ProposedSwap[] memory swaps, Types.SwapPublicInput[] memory swapPublicInputs) = _validateSwaps(
            currentLightClientHeight,
            swapParams,
            overwriteSwaps
        );

        bytes32 compressedLeavesCommitment = EfficientHashLib.hash(blockProofParams.compressedBlockLeaves);
        _verifyZeroKnowledgeProof(
            Types.ProofType.Combined,
            swapPublicInputs,
            Types.LightClientPublicInput({
                previousMmrRoot: blockProofParams.priorMmrRoot,
                newMmrRoot: blockProofParams.newMmrRoot,
                compressedLeavesCommitment: compressedLeavesCommitment,
                tipBlockLeaf: blockProofParams.tipBlockLeaf
            }),
            proof
        );

        emit Events.SwapsUpdated(swaps, Types.SwapUpdateContext.Created);
    }

    /// @notice Submits a batch of swap proofs and adds them to swapCommitments, does not update the light client
    function submitBatchSwapProof(
        Types.SubmitSwapProofParams[] calldata swapParams,
        Types.ProposedSwap[] calldata overwriteSwaps,
        bytes calldata proof
    ) external {
        uint32 currentLightClientHeight = getLightClientHeight();
        (Types.ProposedSwap[] memory swaps, Types.SwapPublicInput[] memory swapPublicInputs) = _validateSwaps(
            currentLightClientHeight,
            swapParams,
            overwriteSwaps
        );

        _verifyZeroKnowledgeProof(Types.ProofType.SwapOnly, swapPublicInputs, getNullLightClientPublicInput(), proof);

        emit Events.SwapsUpdated(swaps, Types.SwapUpdateContext.Created);
    }

    /// @notice Releases locked liquidity for multiple swaps
    function releaseLiquidityBatch(Types.ReleaseLiquidityParams[] calldata paramsArray) external {
        Types.ProposedSwap[] memory updatedSwaps = new Types.ProposedSwap[](paramsArray.length);
        Types.DepositVault[] memory updatedVaults = new Types.DepositVault[](paramsArray.length);

        for (uint256 i = 0; i < paramsArray.length; i++) {
            VaultLib.validateSwapCommitment(paramsArray[i].swap, swapCommitments);
            if (paramsArray[i].swap.state != Types.SwapState.Proved) revert Errors.SwapNotProved();
            if (block.timestamp < paramsArray[i].swap.liquidityUnlockTimestamp) revert Errors.StillInChallengePeriod();

            bytes32 depositVaultCommitment = VaultLib.validateDepositVaultCommitment(
                paramsArray[i].utilizedVault,
                vaultCommitments
            );
            if (depositVaultCommitment != paramsArray[i].swap.depositVaultCommitment) {
                revert Errors.InvalidVaultCommitment();
            }

            Types.BlockLeaf memory swapBlockLeaf = Types.BlockLeaf({
                blockHash: paramsArray[i].swap.swapBitcoinBlockHash,
                height: paramsArray[i].swapBlockHeight,
                cumulativeChainwork: paramsArray[i].swapBlockChainwork
            });

            _ensureBitcoinInclusion(
                swapBlockLeaf,
                paramsArray[i].bitcoinSwapBlockSiblings,
                paramsArray[i].bitcoinSwapBlockPeaks,
                paramsArray[i].swap.confirmationBlocks
            );

            Types.DepositVault memory updatedVault = paramsArray[i].utilizedVault;
            updatedVault.depositAmount = 0;
            updatedVault.depositFee = 0;

            vaultCommitments[updatedVault.vaultIndex] = VaultLib.hashDepositVault(updatedVault);

            updatedVaults[i] = updatedVault;

            Types.ProposedSwap memory updatedSwap = paramsArray[i].swap;
            updatedSwap.state = Types.SwapState.Finalized;
            swapCommitments[paramsArray[i].swap.swapIndex] = VaultLib.hashSwap(updatedSwap);

            accumulatedFeeBalance += paramsArray[i].swap.totalSwapFee;

            if (
                !DEPOSIT_TOKEN.transfer(paramsArray[i].swap.specifiedPayoutAddress, paramsArray[i].swap.totalSwapOutput)
            ) {
                revert Errors.TransferFailed();
            }

            updatedSwaps[i] = updatedSwap;
        }

        // TODO: Does order of events matter here?
        emit Events.SwapsUpdated(updatedSwaps, Types.SwapUpdateContext.Complete);
        emit Events.VaultsUpdated(updatedVaults, Types.VaultUpdateContext.Release);
    }

    function updateLightClient(Types.BlockProofParams calldata blockProofParams, bytes calldata proof) external {
        bytes32 compressedLeavesCommitment = EfficientHashLib.hash(blockProofParams.compressedBlockLeaves);

        VERIFIER.verifyProof(
            CIRCUIT_VERIFICATION_KEY,
            abi.encode(
                Types.ProofPublicInput({
                    proofType: Types.ProofType.LightClientOnly,
                    swaps: new Types.SwapPublicInput[](0),
                    lightClient: Types.LightClientPublicInput({
                        previousMmrRoot: blockProofParams.priorMmrRoot,
                        newMmrRoot: blockProofParams.newMmrRoot,
                        compressedLeavesCommitment: compressedLeavesCommitment,
                        tipBlockLeaf: blockProofParams.tipBlockLeaf
                    })
                })
            ),
            proof
        );
        _updateRoot(
            blockProofParams.priorMmrRoot,
            blockProofParams.newMmrRoot,
            blockProofParams.tipBlockLeaf,
            blockProofParams.compressedBlockLeaves
        );
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

        if (!proveBlockInclusion(params.safeBlockLeaf, params.safeBlockSiblings, params.safeBlockPeaks)) {
            revert Errors.InvalidBlockInclusionProof();
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
            attestedBitcoinBlockHeight: params.safeBlockLeaf.height
        });

        return (vault, VaultLib.hashDepositVault(vault));
    }

    // TODO: add function to do pure block updates

    /// @notice Internal function to finalize a deposit
    function _finalizeDeposit(Types.DepositVault memory vault) internal {
        Types.DepositVault[] memory updatedVaults = new Types.DepositVault[](1);
        updatedVaults[0] = vault;
        emit Events.VaultsUpdated(updatedVaults, Types.VaultUpdateContext.Created);
        if (!DEPOSIT_TOKEN.transferFrom(msg.sender, address(this), vault.depositAmount + vault.depositFee)) {
            revert Errors.TransferFailed();
        }
    }

    /// @notice Internal function to prepare and validate a batch of swap proofs
    function _validateSwaps(
        uint32 currentLightClientHeight,
        Types.SubmitSwapProofParams[] calldata swapParams,
        Types.ProposedSwap[] calldata overwriteSwaps
    ) internal returns (Types.ProposedSwap[] memory swaps, Types.SwapPublicInput[] memory swapPublicInputs) {
        if (swapParams.length == 0) revert Errors.NoSwapsToSubmit();
        swapPublicInputs = new Types.SwapPublicInput[](swapParams.length);
        swaps = new Types.ProposedSwap[](swapParams.length);

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
                swapBitcoinTxid: params.swapBitcoinTxid,
                swapBitcoinBlockHash: params.swapBitcoinBlockLeaf.blockHash,
                depositVaultCommitment: depositVaultCommitment
            });

            _ensureBitcoinInclusion(
                params.swapBitcoinBlockLeaf,
                params.swapBitcoinBlockSiblings,
                params.swapBitcoinBlockPeaks,
                params.vault.confirmationBlocks
            );

            swaps[i] = Types.ProposedSwap({
                swapIndex: swapIndex,
                swapBitcoinBlockHash: params.swapBitcoinBlockLeaf.blockHash,
                confirmationBlocks: params.vault.confirmationBlocks,
                liquidityUnlockTimestamp: uint64(
                    block.timestamp +
                        RiftUtils.calculateChallengePeriod(
                            // The challenge period is based on the worst case reorg which would be to the
                            // depositors originally attested bitcoin block height
                            currentLightClientHeight - params.vault.attestedBitcoinBlockHeight
                        )
                ),
                specifiedPayoutAddress: params.vault.specifiedPayoutAddress,
                totalSwapFee: totalSwapFee,
                totalSwapOutput: totalSwapOutput,
                state: Types.SwapState.Proved,
                depositVaultCommitment: depositVaultCommitment
            });

            bytes32 swapCommitment = VaultLib.hashSwap(swaps[i]);
            if (params.storageStrategy == Types.StorageStrategy.Append) {
                swapCommitments.push(swapCommitment);
            } else if (params.storageStrategy == Types.StorageStrategy.Overwrite) {
                swapCommitments[overwriteSwaps[params.localOverwriteIndex].swapIndex] = swapCommitment;
            }
        }
    }

    function _verifyZeroKnowledgeProof(
        Types.ProofType proofType,
        Types.SwapPublicInput[] memory swapPublicInputs,
        Types.LightClientPublicInput memory lightClientPublicInput,
        bytes calldata proof
    ) internal view {
        VERIFIER.verifyProof(
            CIRCUIT_VERIFICATION_KEY,
            abi.encode(
                Types.ProofPublicInput({
                    proofType: proofType,
                    swaps: swapPublicInputs,
                    lightClient: lightClientPublicInput
                })
            ),
            proof
        );
    }

    function getNullLightClientPublicInput() internal pure returns (Types.LightClientPublicInput memory) {
        return
            Types.LightClientPublicInput({
                previousMmrRoot: bytes32(0),
                newMmrRoot: bytes32(0),
                compressedLeavesCommitment: bytes32(0),
                tipBlockLeaf: Types.BlockLeaf({blockHash: bytes32(0), height: 0, cumulativeChainwork: 0})
            });
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
