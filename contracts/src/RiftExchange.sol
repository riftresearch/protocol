// SPDX-License-Identifier: Unlicensed

pragma solidity =0.8.28;

import "./interfaces/IRiftExchange.sol";
import {ISP1Verifier} from "sp1-contracts/contracts/src/ISP1Verifier.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";

import {EIP712} from "solady/src/utils/EIP712.sol";
import {ERC20} from "solady/src/tokens/ERC20.sol";
import {Ownable} from "solady/src/auth/Ownable.sol";

import {HashLib} from "./libraries/HashLib.sol";
import {PeriodLib} from "./libraries/PeriodLib.sol";
import {BitcoinLightClient} from "./BitcoinLightClient.sol";
import {DataIntegrityLib} from "./libraries/DataIntegrityLib.sol";
import {FeeLib} from "./libraries/FeeLib.sol";
import {MMRProofLib} from "./libraries/MMRProof.sol";
import {BitcoinScriptLib} from "./libraries/BitcoinScriptLib.sol";

/**
 * @title RiftExchange
 * @notice A decentralized exchange for cross-chain Bitcoin<>Tokenized Bitcoin swaps
 * @dev Uses a Bitcoin light client and zero-knowledge proofs for verification of payment
 */
abstract contract RiftExchange is IRiftExchange, EIP712, Ownable, BitcoinLightClient {
    using SafeTransferLib for address;
    using HashLib for DepositVault;
    using HashLib for ProposedSwap;
    using DataIntegrityLib for DepositVault;
    using DataIntegrityLib for ProposedSwap;

    // -----------------------------------------------------------------------
    //                                CONSTANTS
    // -----------------------------------------------------------------------

    uint16 public constant MIN_OUTPUT_SATS = 1000; // to prevent dust errors on btc side
    uint8 public constant MIN_CONFIRMATION_BLOCKS = 2;

    // -----------------------------------------------------------------------
    //                                IMMUTABLES
    // -----------------------------------------------------------------------
    address public immutable ERC20_BTC;
    bytes32 public immutable CIRCUIT_VERIFICATION_KEY;
    address public immutable VERIFIER;

    // -----------------------------------------------------------------------
    //                                 STATE
    // -----------------------------------------------------------------------
    bytes32[] public vaultHashes;
    bytes32[] public swapHashes;
    uint256 public accumulatedFeeBalance;
    address public feeRouterAddress;
    uint16 public takerFeeBips;

    // -----------------------------------------------------------------------
    //                              CONSTRUCTOR
    // -----------------------------------------------------------------------
    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        uint16 _takerFeeBips,
        BlockLeaf memory _tipBlockLeaf
    ) BitcoinLightClient(_mmrRoot, _tipBlockLeaf) {
        _initializeOwner(msg.sender);
        /// @dev Deposit token checks within the contract assume that the token has 8 decimals
        uint8 depositTokenDecimals = ERC20(_depositToken).decimals();
        if (depositTokenDecimals != 8) revert InvalidDepositTokenDecimals(depositTokenDecimals, 8);
        ERC20_BTC = _depositToken;
        CIRCUIT_VERIFICATION_KEY = _circuitVerificationKey;
        VERIFIER = _verifier;
        feeRouterAddress = _feeRouter;
        takerFeeBips = _takerFeeBips;
    }

    /// @dev Returns the domain name and version of the contract, used for EIP712 domain separator
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "RiftExchange";
        version = "0.0.1";
    }

    // -----------------------------------------------------------------------
    //                             EXTERNAL FUNCTIONS
    // -----------------------------------------------------------------------

    /// @notice Sends accumulated protocol fees to the fee router contract
    /// @dev Reverts if there are no fees to pay or if the transfer fails
    function payoutToFeeRouter() external {
        uint256 feeBalance = accumulatedFeeBalance;
        if (feeBalance == 0) revert NoFeeToPay();
        accumulatedFeeBalance = 0;
        ERC20_BTC.safeTransfer(feeRouterAddress, feeBalance);
    }

    function adminSetFeeRouterAddress(address _feeRouter) external onlyOwner {
        feeRouterAddress = _feeRouter;
    }

    function adminSetTakerFeeBips(uint16 _takerFeeBips) external onlyOwner {
        takerFeeBips = _takerFeeBips;
    }

    /// @notice Deposits new liquidity into a new vault
    /// @return The hash of the new deposit
    /// @dev This function requires that the child contract handles token accounting
    function _depositLiquidity(DepositLiquidityParams memory params) internal returns (bytes32) {
        // Determine vault index
        uint256 vaultIndex = vaultHashes.length;

        // Create deposit liquidity request
        (DepositVault memory vault, bytes32 depositHash) = _prepareDeposit(params, vaultIndex);

        // Add deposit hash to vault hashes
        vaultHashes.push(depositHash);

        // Finalize deposit
        DepositVault[] memory updatedVaults = new DepositVault[](1);
        updatedVaults[0] = vault;
        emit VaultsUpdated(updatedVaults, VaultUpdateContext.Created);

        return depositHash;
    }


    /// @notice Withdraws liquidity from a deposit vault after the lockup period
    /// @dev Anyone can call, reverts if vault doesn't exist, is empty, or still in lockup period
    function withdrawLiquidity(DepositVault calldata vault) external {
        vault.checkIntegrity(vaultHashes);
        if (vault.vaultAmount == 0) revert EmptyDepositVault();
        if (block.timestamp < vault.depositUnlockTimestamp) {
            revert DepositStillLocked();
        }

        DepositVault memory updatedVault = vault;
        updatedVault.vaultAmount = 0;
        updatedVault.takerFee = 0;

        vaultHashes[updatedVault.vaultIndex] = updatedVault.hash();

        ERC20_BTC.safeTransfer(vault.ownerAddress, vault.vaultAmount + vault.takerFee);

        DepositVault[] memory updatedVaults = new DepositVault[](1);
        updatedVaults[0] = updatedVault;
        emit VaultsUpdated(updatedVaults, VaultUpdateContext.Withdraw);
    }

    /// @notice Submits a a batch of swap proofs and adds them to swapHashes
    function submitBatchSwapProofWithLightClientUpdate(
        SubmitSwapProofParams[] calldata swapParams,
        BlockProofParams calldata blockProofParams,
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

        (ProposedSwap[] memory swaps, SwapPublicInput[] memory swapPublicInputs) = _validateSwaps(
            proposedLightClientHeight,
            swapParams
        );

        bytes32 compressedLeavesHash = EfficientHashLib.hash(blockProofParams.compressedBlockLeaves);
        verifyZkProof(
            ProofPublicInput({
                proofType: ProofType.Combined,
                swaps: swapPublicInputs,
                lightClient: LightClientPublicInput({
                    previousMmrRoot: blockProofParams.priorMmrRoot,
                    newMmrRoot: blockProofParams.newMmrRoot,
                    compressedLeavesHash: compressedLeavesHash,
                    tipBlockLeaf: blockProofParams.tipBlockLeaf
                })
            }),
            proof
        );

        emit SwapsUpdated(swaps, SwapUpdateContext.Created);
    }

    /// @notice Submits a batch of swap proofs and adds them to swapHashes, does not update the light client
    function submitBatchSwapProof(
        SubmitSwapProofParams[] calldata swapParams,
        bytes calldata proof
    ) external {
        uint32 currentLightClientHeight = getLightClientHeight();
        (ProposedSwap[] memory swaps, SwapPublicInput[] memory swapPublicInputs) = _validateSwaps(
            currentLightClientHeight,
            swapParams
        );

        verifyZkProof(
            ProofPublicInput({
                proofType: ProofType.SwapOnly,
                swaps: swapPublicInputs,
                // null light client public input to align with circuit
                lightClient: LightClientPublicInput({
                    previousMmrRoot: bytes32(0),
                    newMmrRoot: bytes32(0),
                    compressedLeavesHash: bytes32(0),
                    tipBlockLeaf: BlockLeaf({blockHash: bytes32(0), height: 0, cumulativeChainwork: 0})
                })
            }),
            proof
        );
        emit SwapsUpdated(swaps, SwapUpdateContext.Created);
    }

    /// @notice Releases locked liquidity for multiple swaps
    function releaseLiquidityBatch(ReleaseLiquidityParams[] calldata paramsArray) external {
        ProposedSwap[] memory updatedSwaps = new ProposedSwap[](paramsArray.length);
        DepositVault[] memory updatedVaults = new DepositVault[](paramsArray.length);

        for (uint256 i = 0; i < paramsArray.length; i++) {
            paramsArray[i].swap.checkIntegrity(swapHashes);
            if (paramsArray[i].swap.state != SwapState.Proved) revert SwapNotProved();
            if (block.timestamp < paramsArray[i].swap.liquidityUnlockTimestamp) revert StillInChallengePeriod();

            bytes32 depositVaultHash = paramsArray[i].utilizedVault.checkIntegrity(vaultHashes);
            if (depositVaultHash != paramsArray[i].swap.depositVaultHash) {
                revert InvalidVaultHash(paramsArray[i].swap.depositVaultHash, depositVaultHash);
            }

            BlockLeaf memory swapBlockLeaf = paramsArray[i].swap.swapBitcoinBlockLeaf;

            // TODO: consider how to optimize this so this is only called the minimum amount for a given collection of releases
            _verifyBlockInclusionAndConfirmations(
                swapBlockLeaf,
                paramsArray[i].bitcoinSwapBlockSiblings,
                paramsArray[i].bitcoinSwapBlockPeaks,
                paramsArray[i].swap.confirmationBlocks
            );

            DepositVault memory updatedVault = paramsArray[i].utilizedVault;
            updatedVault.vaultAmount = 0;
            updatedVault.takerFee = 0;

            vaultHashes[updatedVault.vaultIndex] = updatedVault.hash();

            updatedVaults[i] = updatedVault;

            ProposedSwap memory updatedSwap = paramsArray[i].swap;
            updatedSwap.state = SwapState.Finalized;
            swapHashes[paramsArray[i].swap.swapIndex] = updatedSwap.hash();

            accumulatedFeeBalance += paramsArray[i].swap.takerFee;

            ERC20_BTC.safeTransfer(paramsArray[i].swap.specifiedPayoutAddress, paramsArray[i].swap.totalSwapOutput);

            updatedSwaps[i] = updatedSwap;
        }

        emit SwapsUpdated(updatedSwaps, SwapUpdateContext.Complete);
        emit VaultsUpdated(updatedVaults, VaultUpdateContext.Release);
    }

    function updateLightClient(BlockProofParams calldata blockProofParams, bytes calldata proof) external {
        bytes32 compressedLeavesHash = EfficientHashLib.hash(blockProofParams.compressedBlockLeaves);

        _updateRoot(
            blockProofParams.priorMmrRoot,
            blockProofParams.newMmrRoot,
            blockProofParams.tipBlockLeaf,
            blockProofParams.compressedBlockLeaves
        );

        verifyZkProof(
            ProofPublicInput({
                proofType: ProofType.LightClientOnly,
                swaps: new SwapPublicInput[](0),
                lightClient: LightClientPublicInput({
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
        DepositLiquidityParams memory params,
        uint256 depositVaultIndex
    ) internal view returns (DepositVault memory, bytes32) {
        uint16 _takerFeeBips = takerFeeBips; // cache
        if (params.depositAmount < FeeLib.calculateMinDepositAmount(_takerFeeBips)) revert DepositAmountTooLow();
        if (params.expectedSats < MIN_OUTPUT_SATS) revert SatOutputTooLow();
        if (params.base.confirmationBlocks < MIN_CONFIRMATION_BLOCKS) revert NotEnoughConfirmationBlocks();
        if (!BitcoinScriptLib.validateScriptPubKey(params.base.btcPayoutScriptPubKey))
            revert InvalidScriptPubKey();

        _verifyBlockInclusion(params.base.safeBlockLeaf, params.safeBlockSiblings, params.safeBlockPeaks);

        uint256 depositFee = FeeLib.calculateFeeFromDeposit(params.depositAmount, _takerFeeBips);

        DepositVault memory vault = DepositVault({
            vaultIndex: depositVaultIndex,
            depositTimestamp: uint64(block.timestamp),
            depositUnlockTimestamp: uint64(
                block.timestamp + PeriodLib.calculateDepositLockupPeriod(params.base.confirmationBlocks)
            ),
            vaultAmount: params.depositAmount - depositFee,
            takerFee: depositFee,
            expectedSats: params.expectedSats,
            btcPayoutScriptPubKey: params.base.btcPayoutScriptPubKey,
            specifiedPayoutAddress: params.specifiedPayoutAddress,
            ownerAddress: params.base.depositOwnerAddress,
            salt: EfficientHashLib.hash(_domainSeparator(), params.base.depositSalt, bytes32(depositVaultIndex)),
            confirmationBlocks: params.base.confirmationBlocks,
            attestedBitcoinBlockHeight: params.base.safeBlockLeaf.height
        });

        return (vault, vault.hash());
    }



    /// @notice Internal function to prepare and validate a batch of swap proofs
    function _validateSwaps(
        uint32 proposedLightClientHeight,
        SubmitSwapProofParams[] calldata swapParams
    ) internal returns (ProposedSwap[] memory swaps, SwapPublicInput[] memory swapPublicInputs) {
        if (swapParams.length == 0) revert NoSwapsToSubmit();
        swapPublicInputs = new SwapPublicInput[](swapParams.length);
        swaps = new ProposedSwap[](swapParams.length);

        uint256 initialSwapIndexPointer = swapHashes.length;
        for (uint256 i = 0; i < swapParams.length; i++) {
            uint256 swapIndex = initialSwapIndexPointer + i;
            SubmitSwapProofParams calldata params = swapParams[i];

            bytes32 depositVaultHash = params.vault.checkIntegrity(vaultHashes);

            swapPublicInputs[i] = SwapPublicInput({
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

            swaps[i] = ProposedSwap({
                swapIndex: swapIndex,
                swapBitcoinBlockLeaf: params.swapBitcoinBlockLeaf,
                confirmationBlocks: params.vault.confirmationBlocks,
                liquidityUnlockTimestamp: uint64(
                    block.timestamp +
                        PeriodLib.calculateChallengePeriod(
                            // The challenge period is based on the worst case reorg which would be to the
                            // depositors originally attested bitcoin block height
                            proposedLightClientHeight - params.vault.attestedBitcoinBlockHeight
                        )
                ),
                specifiedPayoutAddress: params.vault.specifiedPayoutAddress,
                totalSwapOutput: params.vault.vaultAmount,
                takerFee: params.vault.takerFee,
                state: SwapState.Proved,
                depositVaultHash: depositVaultHash
            });

            bytes32 swapHash = swaps[i].hash();
            swapHashes.push(swapHash);
        }
    }

    // Convenience function to verify a rift proof via eth_call
    function verifyZkProof(ProofPublicInput memory proofPublicInput, bytes calldata proof) public view {
        ISP1Verifier(VERIFIER).verifyProof(CIRCUIT_VERIFICATION_KEY, abi.encode(proofPublicInput), proof);
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


    function serializeLightClientPublicInput(
        LightClientPublicInput memory input
    ) external pure returns (bytes memory) {
        return abi.encode(input);
    }
}
