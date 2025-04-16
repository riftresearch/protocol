// SPDX-License-Identifier: Unlicensed

pragma solidity =0.8.28;

import {ISP1Verifier} from "sp1-contracts/contracts/src/ISP1Verifier.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";
import {Ownable} from "solady/src/auth/Ownable.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";

import {Constants} from "./libraries/Constants.sol";
import {Errors} from "./libraries/Errors.sol";
import {Types} from "./libraries/Types.sol";
import {Events} from "./libraries/Events.sol";
import {VaultLib} from "./libraries/VaultLib.sol";
import {RiftUtils} from "./libraries/RiftUtils.sol";
import {BitcoinLightClient} from "./BitcoinLightClient.sol";
import {LightClientVerificationLib} from "./libraries/LightClientVerificationLib.sol";

/**
 * @title RiftExchange
 * @author alpinevm <https://github.com/alpinevm>
 * @author spacegod <https://github.com/bruidbarrett>
 * @notice A decentralized exchange for cross-chain Bitcoin<>Tokenized Bitcoin swaps
 * @dev Uses a Bitcoin light client and zero-knowledge proofs for verification of payment
 */
contract RiftExchange is BitcoinLightClient, Ownable {
    using SafeTransferLib for address;
    // -----------------------------------------------------------------------
    //                                IMMUTABLES
    // -----------------------------------------------------------------------
    address public immutable ERC20_BTC;
    bytes32 public immutable CIRCUIT_VERIFICATION_KEY;
    ISP1Verifier public immutable VERIFIER;

    // -----------------------------------------------------------------------
    //                                 STATE
    // -----------------------------------------------------------------------
    bytes32[] public vaultHashes;
    bytes32[] public swapHashes;
    uint256 public accumulatedFeeBalance;
    address public feeRouterAddress;

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
        _initializeOwner(msg.sender);
        ERC20_BTC = _depositToken;
        CIRCUIT_VERIFICATION_KEY = _circuitVerificationKey;
        VERIFIER = ISP1Verifier(_verifier);
        feeRouterAddress = _feeRouter;
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

        ERC20_BTC.safeTransfer(feeRouterAddress, feeBalance);
    }

    function setFeeRouterAddress(address _feeRouter) external onlyOwner {
        feeRouterAddress = _feeRouter;
    }

    /// @notice Deposits new liquidity into a new vault
    /// @return The hash of the new deposit
    function depositLiquidity(Types.DepositLiquidityParams calldata params) external returns (bytes32) {
        // Determine vault index
        uint256 vaultIndex = vaultHashes.length;

        // Create deposit liquidity request
        (Types.DepositVault memory vault, bytes32 depositHash) = _prepareDeposit(params, vaultIndex);

        // Add deposit hash to vault hashes
        vaultHashes.push(depositHash);

        // Finalize deposit
        _finalizeDeposit(vault);

        return depositHash;
    }

    /// @notice Deposits new liquidity by overwriting an existing empty vault
    /// @return The hash of the new deposit
    function depositLiquidityWithOverwrite(
        Types.DepositLiquidityWithOverwriteParams calldata params
    ) external returns (bytes32) {
        // Ensure passed vault is real and overwritable
        VaultLib.validateDepositVaultHash(params.overwriteVault, vaultHashes);
        if (params.overwriteVault.depositAmount != 0) revert Errors.DepositVaultNotOverwritable();

        // Create deposit liquidity request
        uint256 vaultIndex = params.overwriteVault.vaultIndex;
        (Types.DepositVault memory vault, bytes32 depositHash) = _prepareDeposit(params.depositParams, vaultIndex);

        // Overwrite deposit vault
        vaultHashes[vaultIndex] = depositHash;

        // Finalize deposit
        _finalizeDeposit(vault);

        return depositHash;
    }

    /// @notice Withdraws liquidity from a deposit vault after the lockup period
    /// @dev Anyone can call, reverts if vault doesn't exist, is empty, or still in lockup period
    function withdrawLiquidity(Types.DepositVault calldata vault) external {
        VaultLib.validateDepositVaultHash(vault, vaultHashes);
        if (vault.depositAmount == 0) revert Errors.EmptyDepositVault();
        if (block.timestamp < vault.depositUnlockTimestamp) {
            revert Errors.DepositStillLocked();
        }

        Types.DepositVault memory updatedVault = vault;
        updatedVault.depositAmount = 0;
        updatedVault.depositFee = 0;

        vaultHashes[updatedVault.vaultIndex] = VaultLib.hashDepositVault(updatedVault);

        ERC20_BTC.safeTransfer(vault.ownerAddress, vault.depositAmount);

        Types.DepositVault[] memory updatedVaults = new Types.DepositVault[](1);
        updatedVaults[0] = updatedVault;
        emit Events.VaultsUpdated(updatedVaults, Types.VaultUpdateContext.Withdraw);
    }

    /// @notice Submits a a batch of swap proofs and adds them to swapHashes or overwrites an existing completed swap hash
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

        uint32 proposedLightClientHeight = blockProofParams.tipBlockLeaf.height;

        (Types.ProposedSwap[] memory swaps, Types.SwapPublicInput[] memory swapPublicInputs) = _validateSwaps(
            proposedLightClientHeight,
            swapParams,
            overwriteSwaps
        );

        bytes32 compressedLeavesHash = EfficientHashLib.hash(blockProofParams.compressedBlockLeaves);
        verifyZkProof(
            Types.ProofPublicInput({
                proofType: Types.ProofType.Combined,
                swaps: swapPublicInputs,
                lightClient: Types.LightClientPublicInput({
                    previousMmrRoot: blockProofParams.priorMmrRoot,
                    newMmrRoot: blockProofParams.newMmrRoot,
                    compressedLeavesHash: compressedLeavesHash,
                    tipBlockLeaf: blockProofParams.tipBlockLeaf
                })
            }),
            proof
        );

        emit Events.SwapsUpdated(swaps, Types.SwapUpdateContext.Created);
    }

    /// @notice Submits a batch of swap proofs and adds them to swapHashes, does not update the light client
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

        verifyZkProof(
            Types.ProofPublicInput({
                proofType: Types.ProofType.SwapOnly,
                swaps: swapPublicInputs,
                lightClient: getNullLightClientPublicInput()
            }),
            proof
        );
        emit Events.SwapsUpdated(swaps, Types.SwapUpdateContext.Created);
    }

    /// @notice Releases locked liquidity for multiple swaps
    function releaseLiquidityBatch(Types.ReleaseLiquidityParams[] calldata paramsArray) external {
        Types.ProposedSwap[] memory updatedSwaps = new Types.ProposedSwap[](paramsArray.length);
        Types.DepositVault[] memory updatedVaults = new Types.DepositVault[](paramsArray.length);

        for (uint256 i = 0; i < paramsArray.length; i++) {
            VaultLib.validateSwapHash(paramsArray[i].swap, swapHashes);
            if (paramsArray[i].swap.state != Types.SwapState.Proved) revert Errors.SwapNotProved();
            if (block.timestamp < paramsArray[i].swap.liquidityUnlockTimestamp) revert Errors.StillInChallengePeriod();

            bytes32 depositVaultHash = VaultLib.validateDepositVaultHash(paramsArray[i].utilizedVault, vaultHashes);
            if (depositVaultHash != paramsArray[i].swap.depositVaultHash) {
                revert Errors.InvalidVaultHash(paramsArray[i].swap.depositVaultHash, depositVaultHash);
            }

            Types.BlockLeaf memory swapBlockLeaf = paramsArray[i].swap.swapBitcoinBlockLeaf;

            // TODO: consider how to optimize this so this is only called the minimum amount for a given collection of releases
            _verifyBlockInclusionAndConfirmations(
                swapBlockLeaf,
                paramsArray[i].bitcoinSwapBlockSiblings,
                paramsArray[i].bitcoinSwapBlockPeaks,
                paramsArray[i].swap.confirmationBlocks
            );

            Types.DepositVault memory updatedVault = paramsArray[i].utilizedVault;
            updatedVault.depositAmount = 0;
            updatedVault.depositFee = 0;

            vaultHashes[updatedVault.vaultIndex] = VaultLib.hashDepositVault(updatedVault);

            updatedVaults[i] = updatedVault;

            Types.ProposedSwap memory updatedSwap = paramsArray[i].swap;
            updatedSwap.state = Types.SwapState.Finalized;
            swapHashes[paramsArray[i].swap.swapIndex] = VaultLib.hashSwap(updatedSwap);

            accumulatedFeeBalance += paramsArray[i].swap.totalSwapFee;

            ERC20_BTC.safeTransfer(paramsArray[i].swap.specifiedPayoutAddress, paramsArray[i].swap.totalSwapOutput);

            updatedSwaps[i] = updatedSwap;
        }

        emit Events.SwapsUpdated(updatedSwaps, Types.SwapUpdateContext.Complete);
        emit Events.VaultsUpdated(updatedVaults, Types.VaultUpdateContext.Release);
    }

    function updateLightClient(Types.BlockProofParams calldata blockProofParams, bytes calldata proof) external {
        bytes32 compressedLeavesHash = EfficientHashLib.hash(blockProofParams.compressedBlockLeaves);

        _updateRoot(
            blockProofParams.priorMmrRoot,
            blockProofParams.newMmrRoot,
            blockProofParams.tipBlockLeaf,
            blockProofParams.compressedBlockLeaves
        );

        verifyZkProof(
            Types.ProofPublicInput({
                proofType: Types.ProofType.LightClientOnly,
                swaps: new Types.SwapPublicInput[](0),
                lightClient: Types.LightClientPublicInput({
                    previousMmrRoot: blockProofParams.priorMmrRoot,
                    newMmrRoot: blockProofParams.newMmrRoot,
                    compressedLeavesHash: compressedLeavesHash,
                    tipBlockLeaf: blockProofParams.tipBlockLeaf
                })
            }),
            proof
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
        if (params.confirmationBlocks < Constants.MIN_CONFIRMATION_BLOCKS) revert Errors.NotEnoughConfirmationBlocks();
        if (!LightClientVerificationLib.validateScriptPubKey(params.btcPayoutScriptPubKey))
            revert Errors.InvalidScriptPubKey();

        _verifyBlockInclusion(params.safeBlockLeaf, params.safeBlockSiblings, params.safeBlockPeaks);

        uint256 depositFee = RiftUtils.calculateFeeFromInitialDeposit(params.depositAmount);

        Types.DepositVault memory vault = Types.DepositVault({
            vaultIndex: depositVaultIndex,
            depositTimestamp: uint64(block.timestamp),
            depositUnlockTimestamp: uint64(
                block.timestamp + RiftUtils.calculateDepositLockupPeriod(params.confirmationBlocks)
            ),
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

    /// @notice Internal function to finalize a deposit
    function _finalizeDeposit(Types.DepositVault memory vault) internal {
        Types.DepositVault[] memory updatedVaults = new Types.DepositVault[](1);
        updatedVaults[0] = vault;
        emit Events.VaultsUpdated(updatedVaults, Types.VaultUpdateContext.Created);
        ERC20_BTC.safeTransferFrom(msg.sender, address(this), vault.depositAmount + vault.depositFee);
    }

    /// @notice Internal function to prepare and validate a batch of swap proofs
    function _validateSwaps(
        uint32 proposedLightClientHeight,
        Types.SubmitSwapProofParams[] calldata swapParams,
        Types.ProposedSwap[] calldata overwriteSwaps
    ) internal returns (Types.ProposedSwap[] memory swaps, Types.SwapPublicInput[] memory swapPublicInputs) {
        if (swapParams.length == 0) revert Errors.NoSwapsToSubmit();
        swapPublicInputs = new Types.SwapPublicInput[](swapParams.length);
        swaps = new Types.ProposedSwap[](swapParams.length);

        uint256 swapIndexPointer = swapHashes.length;
        for (uint256 i = 0; i < swapParams.length; i++) {
            uint256 swapIndex = swapIndexPointer; // default is append
            Types.SubmitSwapProofParams calldata params = swapParams[i];
            if (params.storageStrategy == Types.StorageStrategy.Append) {
                swapIndexPointer++;
            } else if (params.storageStrategy == Types.StorageStrategy.Overwrite) {
                VaultLib.validateSwapHash(overwriteSwaps[params.localOverwriteIndex], swapHashes);
                if (overwriteSwaps[params.localOverwriteIndex].state != Types.SwapState.Finalized) {
                    revert Errors.CannotOverwriteOngoingSwap();
                }
                swapIndex = overwriteSwaps[params.localOverwriteIndex].swapIndex;
            }

            (uint256 totalSwapOutput, uint256 totalSwapFee) = VaultLib.calculateSwapTotals(params.vault);
            bytes32 depositVaultHash = VaultLib.validateDepositVaultHash(params.vault, vaultHashes);

            swapPublicInputs[i] = Types.SwapPublicInput({
                swapBitcoinTxid: params.swapBitcoinTxid,
                swapBitcoinBlockHash: params.swapBitcoinBlockLeaf.blockHash,
                depositVaultHash: depositVaultHash
            });

            _verifyBlockInclusionAndConfirmations(
                params.swapBitcoinBlockLeaf,
                params.swapBitcoinBlockSiblings,
                params.swapBitcoinBlockPeaks,
                params.vault.confirmationBlocks
            );

            swaps[i] = Types.ProposedSwap({
                swapIndex: swapIndex,
                swapBitcoinBlockLeaf: params.swapBitcoinBlockLeaf,
                confirmationBlocks: params.vault.confirmationBlocks,
                liquidityUnlockTimestamp: uint64(
                    block.timestamp +
                        RiftUtils.calculateChallengePeriod(
                            // The challenge period is based on the worst case reorg which would be to the
                            // depositors originally attested bitcoin block height
                            proposedLightClientHeight - params.vault.attestedBitcoinBlockHeight
                        )
                ),
                specifiedPayoutAddress: params.vault.specifiedPayoutAddress,
                totalSwapFee: totalSwapFee,
                totalSwapOutput: totalSwapOutput,
                state: Types.SwapState.Proved,
                depositVaultHash: depositVaultHash
            });

            bytes32 swapHash = VaultLib.hashSwap(swaps[i]);
            if (params.storageStrategy == Types.StorageStrategy.Append) {
                swapHashes.push(swapHash);
            } else if (params.storageStrategy == Types.StorageStrategy.Overwrite) {
                swapHashes[overwriteSwaps[params.localOverwriteIndex].swapIndex] = swapHash;
            }
        }
    }

    // Convenience function to verify a rift proof via eth_call
    function verifyZkProof(Types.ProofPublicInput memory proofPublicInput, bytes calldata proof) public view {
        VERIFIER.verifyProof(CIRCUIT_VERIFICATION_KEY, abi.encode(proofPublicInput), proof);
    }

    function getNullLightClientPublicInput() internal pure returns (Types.LightClientPublicInput memory) {
        return
            Types.LightClientPublicInput({
                previousMmrRoot: bytes32(0),
                newMmrRoot: bytes32(0),
                compressedLeavesHash: bytes32(0),
                tipBlockLeaf: Types.BlockLeaf({blockHash: bytes32(0), height: 0, cumulativeChainwork: 0})
            });
    }

    // -----------------------------------------------------------------------
    //                              READ FUNCTIONS
    // -----------------------------------------------------------------------

    function getVaultHashesLength() external view returns (uint256) {
        return vaultHashes.length;
    }

    function getSwapHashesLength() external view returns (uint256) {
        return swapHashes.length;
    }

    function getVaultHash(uint256 vaultIndex) external view returns (bytes32) {
        return vaultHashes[vaultIndex];
    }

    function getSwapHash(uint256 swapIndex) external view returns (bytes32) {
        return swapHashes[swapIndex];
    }

    function serializeLightClientPublicInput(
        Types.LightClientPublicInput memory input
    ) external pure returns (bytes memory) {
        return abi.encode(input);
    }
}
