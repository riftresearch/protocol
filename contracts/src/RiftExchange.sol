// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {console} from "forge-std/console.sol";
import {ISP1Verifier} from "sp1-contracts/ISP1Verifier.sol";
import {IERC20} from "openzeppelin/contracts/interfaces/IERC20.sol";
import {IERC20Metadata} from "openzeppelin/contracts/interfaces/IERC20Metadata.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

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
    // --------- IMMUTABLES --------- //
    IERC20 public immutable DEPOSIT_TOKEN;
    uint8 public immutable TOKEN_DECIMALS;
    bytes32 public immutable CIRCUIT_VERIFICATION_KEY;
    ISP1Verifier public immutable VERIFIER;
    address public immutable FEE_ROUTER_ADDRESS;

    // --------- STATE --------- //
    bytes32[] public vaultCommitments;
    bytes32[] public swapCommitments;
    uint256 public accumulatedFeeBalance;

    //--------- CONSTRUCTOR ---------//
    constructor(
        bytes32 _mmrRoot,
        Types.BlockLeaf memory _initialCheckpointLeaf,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter
    ) BitcoinLightClient(_mmrRoot, _initialCheckpointLeaf) {
        DEPOSIT_TOKEN = IERC20(_depositToken);
        TOKEN_DECIMALS = IERC20Metadata(_depositToken).decimals();
        CIRCUIT_VERIFICATION_KEY = _circuitVerificationKey;
        VERIFIER = ISP1Verifier(_verifier);
        FEE_ROUTER_ADDRESS = _feeRouter;
    }

    //--------- WRITE FUNCTIONS ---------//
    /// @notice Sends accumulated protocol fees to the fee router contract
    /// @dev Reverts if there are no fees to pay or if the transfer fails
    function payoutToFeeRouter() public {
        uint256 feeBalance = accumulatedFeeBalance;
        if (feeBalance == 0) revert Errors.NoFeeToPay();
        accumulatedFeeBalance = 0;
        if (!DEPOSIT_TOKEN.transfer(FEE_ROUTER_ADDRESS, feeBalance)) revert Errors.TransferFailed();
    }

    /// @notice Deposits new liquidity into a new vault
    /// @param specifiedPayoutAddress Address to receive swap proceeds
    /// @param depositAmount Amount of ERC20 tokens to deposit including fee
    /// @param expectedSats Expected BTC output in satoshis
    /// @param btcPayoutScriptPubKey Bitcoin script for receiving BTC
    /// @param depositSalt User generated salt for vault nonce
    function depositLiquidity(
        address specifiedPayoutAddress,
        uint256 depositAmount,
        uint64 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        bytes32 depositSalt,
        uint8 confirmationBlocks,
        Types.BlockLeaf calldata tipBlockLeaf,
        bytes32[] calldata tipBlockSiblings,
        bytes32[] calldata tipBlockPeaks
    ) public {
        // [0] create deposit liquidity request
        (Types.DepositVault memory vault, bytes32 depositHash) = _prepareDeposit(
            specifiedPayoutAddress,
            depositAmount,
            expectedSats,
            btcPayoutScriptPubKey,
            vaultCommitments.length,
            depositSalt,
            confirmationBlocks,
            tipBlockLeaf,
            tipBlockSiblings,
            tipBlockPeaks
        );

        // [1] add deposit hash to vault commitments
        vaultCommitments.push(depositHash);

        // [2] finalize deposit
        _finalizeDeposit(vault);
    }

    /// @notice Deposits new liquidity by overwriting an existing empty vault
    /// @param overwriteVault Existing empty vault to overwrite
    /// @dev Identical to depositLiquidity, but allows for overwriting an existing empty vault
    function depositLiquidityWithOverwrite(
        address specifiedPayoutAddress,
        uint256 depositAmount,
        uint64 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        bytes32 depositSalt,
        uint8 confirmationBlocks,
        Types.BlockLeaf calldata tipBlockLeaf,
        bytes32[] calldata tipBlockSiblings,
        bytes32[] calldata tipBlockPeaks,
        Types.DepositVault calldata overwriteVault
    ) public {
        // [0] create deposit liquidity request
        (Types.DepositVault memory vault, bytes32 depositHash) = _prepareDeposit(
            specifiedPayoutAddress,
            depositAmount,
            expectedSats,
            btcPayoutScriptPubKey,
            overwriteVault.vaultIndex,
            depositSalt,
            confirmationBlocks,
            tipBlockLeaf,
            tipBlockSiblings,
            tipBlockPeaks
        );

        // [1] ensure passed vault is real and overwritable
        VaultLib.validateDepositVaultCommitment(overwriteVault, vaultCommitments);
        if (overwriteVault.depositAmount != 0) revert Errors.DepositVaultNotOverwritable();

        // [2] overwrite deposit vault
        vaultCommitments[overwriteVault.vaultIndex] = depositHash;

        // [3] finalize deposit
        _finalizeDeposit(vault);
    }

    /// @notice Checks invariants and creates new deposit vault struct
    /// @dev Validates deposit amounts and creates vault structure
    /// @return Tuple of the new vault and its commitment hash
    function _prepareDeposit(
        address specifiedPayoutAddress,
        uint256 depositAmount,
        uint64 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        uint256 depositVaultIndex,
        bytes32 depositSalt,
        uint8 confirmationBlocks,
        Types.BlockLeaf calldata tipBlockLeaf,
        bytes32[] calldata tipBlockSiblings,
        bytes32[] calldata tipBlockPeaks
    ) internal view returns (Types.DepositVault memory, bytes32) {
        // [0] ensure deposit amount is greater than min protocol fee
        if (depositAmount < Constants.MIN_DEPOSIT_AMOUNT) revert Errors.DepositAmountTooLow();

        // [1] ensure expected sat output is above minimum to prevent dust errors
        if (expectedSats < Constants.MIN_OUTPUT_SATS) revert Errors.SatOutputTooLow();

        // [2] ensure scriptPubKey is valid
        if (!VaultLib.validateP2WPKHScriptPubKey(btcPayoutScriptPubKey)) revert Errors.InvalidScriptPubKey();

        // [3] ensure tip block is part of the longest chain
        if (!_proveBlockInclusionAtTip(tipBlockLeaf, tipBlockSiblings, tipBlockPeaks))
            revert Errors.InvalidTipBlockInclusionProof();

        uint256 depositFee = RiftUtils.calculateFeeFromInitialDeposit(depositAmount);

        Types.DepositVault memory vault = Types.DepositVault({
            vaultIndex: depositVaultIndex,
            depositTimestamp: uint64(block.timestamp),
            depositAmount: depositAmount - depositFee,
            depositFee: depositFee,
            expectedSats: expectedSats,
            btcPayoutScriptPubKey: btcPayoutScriptPubKey,
            specifiedPayoutAddress: specifiedPayoutAddress,
            ownerAddress: msg.sender,
            /// @dev Nonce prevents replay attacks by combining:
            /// 1. depositSalt - LP-provided entropy, unknown before deposit
            /// 2. depositVaultIndex - prevents same-block collisions
            /// 3. chainId - prevents cross-chain collisions
            /// While a random salt from the LP would be sufficient for security,
            /// including the vault index and chain ID ensures protocol safety even if
            /// an LP uses a predictable salt. LPs are incentivized to use random salts
            /// to protect their own liquidity.
            nonce: EfficientHashLib.hash(depositSalt, bytes32(depositVaultIndex), bytes32(uint256(block.chainid))),
            confirmationBlocks: confirmationBlocks,
            attestedBitcoinBlockHeight: tipBlockLeaf.height
        });
        return (vault, VaultLib.hashDepositVault(vault));
    }

    /// @notice Completes deposit by emitting event and transferring tokens
    function _finalizeDeposit(Types.DepositVault memory vault) internal {
        emit Events.VaultUpdated(vault, Types.VaultUpdateContext.Created);
        if (!DEPOSIT_TOKEN.transferFrom(msg.sender, address(this), vault.depositAmount + vault.depositFee))
            revert Errors.TransferFailed();
    }

    /// @notice Withdraws liquidity from a deposit vault after the lockup period
    /// @param vault The deposit vault to withdraw from
    /// @dev Anyone can call, reverts if vault doesn't exist, is empty, or still in lockup period
    function withdrawLiquidity(Types.DepositVault calldata vault) public {
        // [0] validate deposit vault exists
        VaultLib.validateDepositVaultCommitment(vault, vaultCommitments);

        // [1] ensure deposit amount is non-zero
        if (vault.depositAmount == 0) revert Errors.EmptyDepositVault();

        // [2] ensure the deposit vault is not time locked
        if (block.timestamp < vault.depositTimestamp + Constants.DEPOSIT_LOCKUP_PERIOD)
            revert Errors.DepositStillLocked();

        // [3] update deposit vault commitment
        Types.DepositVault memory updatedVault = vault;
        updatedVault.depositAmount = 0;
        updatedVault.depositFee = 0;
        bytes32 updatedVaultHash = VaultLib.hashDepositVault(updatedVault);
        vaultCommitments[vault.vaultIndex] = updatedVaultHash;

        // [4] transfer funds to vault owner
        if (!DEPOSIT_TOKEN.transfer(vault.ownerAddress, vault.depositAmount)) {
            revert Errors.TransferFailed();
        }

        emit Events.VaultUpdated(updatedVault, Types.VaultUpdateContext.Withdraw);
    }

    /// @notice Internal function to prepare and validate a new swap
    /// @return swap The prepared swap struct
    /// @return updatedSwapHash The hash of the prepared swap
    function _validateSwap(
        uint256 swapIndex,
        bytes32 swapBitcoinBlockHash,
        bytes32 swapBitcoinTxid,
        Types.DepositVault calldata vault,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        bytes calldata proof,
        bytes calldata compressedBlockLeaves,
        Types.BlockLeaf calldata tipBlockLeaf,
        bytes32[] calldata tipBlockSiblings,
        bytes32[] calldata tipBlockPeaks
    ) internal returns (Types.ProposedSwap memory swap, bytes32 updatedSwapHash) {
        // [0] Validate various parameters align with what requested makers have set (this could be done in circuit)
        uint64 oldestDepositorAttestedBitcoinBlockHeight = vault.attestedBitcoinBlockHeight;

        (uint256 totalSwapOutput, uint256 totalSwapFee) = VaultLib.calculateSwapTotals(vault);

        // [1] create deposit vault commitment, while doing so validate that the vaults hash to
        // their commitments
        bytes32 aggregateVaultCommitment = VaultLib.validateDepositVaultCommitment(vault, vaultCommitments);

        // [2] create compressed leaves commitment
        bytes32 compressedLeavesCommitment = EfficientHashLib.hash(compressedBlockLeaves);

        // [3] craft public inputs and verify proof
        bytes memory publicInputs = abi.encode(
            Types.SwapProofPublicInputs({
                confirmationBlocks: vault.confirmationBlocks,
                swapBitcoinBlockHash: swapBitcoinBlockHash,
                swapBitcoinTxid: swapBitcoinTxid,
                aggregateVaultCommitment: aggregateVaultCommitment,
                specifiedPayoutAddress: vault.specifiedPayoutAddress,
                totalSwapFee: totalSwapFee,
                totalSwapOutput: totalSwapOutput,
                previousMmrRoot: priorMmrRoot,
                newMmrRoot: newMmrRoot,
                compressedLeavesCommitment: compressedLeavesCommitment
            })
        );

        VERIFIER.verifyProof(CIRCUIT_VERIFICATION_KEY, publicInputs, proof);
        _updateRoot(priorMmrRoot, newMmrRoot, compressedBlockLeaves);

        if (!_proveBlockInclusionAtTip(tipBlockLeaf, tipBlockSiblings, tipBlockPeaks))
            revert Errors.InvalidTipBlockInclusionProof();

        // [4] calculate block delta
        uint64 attestedBitcoinBlockHeightDelta = tipBlockLeaf.height - oldestDepositorAttestedBitcoinBlockHeight;

        // [5] create the new swap
        swap = Types.ProposedSwap({
            swapIndex: swapIndex,
            aggregateVaultCommitment: aggregateVaultCommitment,
            swapBitcoinBlockHash: swapBitcoinBlockHash,
            confirmationBlocks: vault.confirmationBlocks,
            liquidityUnlockTimestamp: uint64(
                block.timestamp + RiftUtils.calculateChallengePeriod(attestedBitcoinBlockHeightDelta)
            ),
            specifiedPayoutAddress: vault.specifiedPayoutAddress,
            totalSwapFee: totalSwapFee,
            totalSwapOutput: totalSwapOutput,
            state: Types.SwapState.Proved,
            depositVaultNonce: vault.nonce
        });

        updatedSwapHash = VaultLib.hashSwap(swap);
    }

    /// @notice Submits a new swap proof and adds it to swapCommitments
    /// @param swapBitcoinTxid Txid of the Bitcoin transaction containing the swap
    /// @param swapBitcoinBlockHash Hash of the Bitcoin block containing the swap
    /// @param vault Deposit vault being used in the swap
    /// @param priorMmrRoot Previous MMR root used to generate this swap proof
    /// @param newMmrRoot Updated MMR root at least incluing up to the confirmation block
    /// @param proof ZK proof validating the swap
    /// @param compressedBlockLeaves Compressed block data for MMR Data Availability
    function submitSwapProof(
        bytes32 swapBitcoinTxid,
        bytes32 swapBitcoinBlockHash,
        Types.DepositVault calldata vault,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        bytes calldata proof,
        bytes calldata compressedBlockLeaves,
        Types.BlockLeaf calldata tipBlockLeaf,
        bytes32[] calldata tipBlockSiblings,
        bytes32[] calldata tipBlockPeaks
    ) public {
        // [0] validate swap proof
        (Types.ProposedSwap memory swap, bytes32 updatedSwapHash) = _validateSwap(
            swapCommitments.length,
            swapBitcoinBlockHash,
            swapBitcoinTxid,
            vault,
            priorMmrRoot,
            newMmrRoot,
            proof,
            compressedBlockLeaves,
            tipBlockLeaf,
            tipBlockSiblings,
            tipBlockPeaks
        );

        // [1] update swap commitments with updated swap hash
        swapCommitments.push(updatedSwapHash);
        emit Events.SwapUpdated(swap, Types.SwapUpdateContext.Created);
    }

    /// @notice Same as submitSwapProof but overwrites an existing completed swap commitment
    /// @param overwriteSwap Existing completed swap to overwrite
    /// @dev All other parameters are identical to submitSwapProof
    function submitSwapProofWithOverwrite(
        bytes32 swapBitcoinBlockHash,
        bytes32 swapBitcoinTxid,
        Types.DepositVault calldata vault,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        bytes calldata proof,
        bytes calldata compressedBlockLeaves,
        Types.BlockLeaf calldata tipBlockLeaf,
        bytes32[] calldata tipBlockSiblings,
        bytes32[] calldata tipBlockPeaks,
        Types.ProposedSwap calldata overwriteSwap
    ) public {
        // [0] validate overwrite swap exists and is completed
        VaultLib.validateSwapCommitment(overwriteSwap, swapCommitments);
        if (overwriteSwap.state != Types.SwapState.Completed) revert Errors.CannotOverwriteOnGoingSwap();

        // [1] validate swap proof
        (Types.ProposedSwap memory swap, bytes32 updatedSwapHash) = _validateSwap(
            overwriteSwap.swapIndex,
            swapBitcoinBlockHash,
            swapBitcoinTxid,
            vault,
            priorMmrRoot,
            newMmrRoot,
            proof,
            compressedBlockLeaves,
            tipBlockLeaf,
            tipBlockSiblings,
            tipBlockPeaks
        );

        // [2] update swap commitments with updated swap hash
        swapCommitments[overwriteSwap.swapIndex] = updatedSwapHash;
        emit Events.SwapUpdated(swap, Types.SwapUpdateContext.Created);
    }

    function releaseLiquidity(
        Types.ProposedSwap calldata swap,
        uint256 swapBlockChainwork,
        uint32 swapBlockHeight,
        bytes32[] calldata bitcoinSwapBlockSiblings,
        bytes32[] calldata bitcoinSwapBlockPeaks,
        Types.BlockLeaf calldata bitcoinConfirmationBlockLeaf,
        bytes32[] calldata bitcoinConfirmationBlockSiblings,
        bytes32[] calldata bitcoinConfirmationBlockPeaks,
        Types.DepositVault calldata utilizedVault,
        uint32 tipBlockHeight
    ) public {
        // [0] validate swaps exists
        VaultLib.validateSwapCommitment(swap, swapCommitments);

        // [1] validate swap has been proved
        if (swap.state != Types.SwapState.Proved) {
            revert Errors.SwapNotProved();
        }

        // [2] ensure challenge period has passed since proof submission
        if (block.timestamp < swap.liquidityUnlockTimestamp) {
            revert Errors.StillInChallengePeriod();
        }

        Types.BlockLeaf memory swapBlockLeaf = Types.BlockLeaf({
            blockHash: swap.swapBitcoinBlockHash,
            height: swapBlockHeight,
            cumulativeChainwork: swapBlockChainwork
        });

        // [3] ensure swap block is part of longest chain
        if (!_proveBlockInclusion(swapBlockLeaf, bitcoinSwapBlockSiblings, bitcoinSwapBlockPeaks, tipBlockHeight))
            revert Errors.InvalidSwapBlockInclusionProof();

        // [4] ensure the supposed confirmation block is part of the longest chain
        if (
            !_proveBlockInclusion(
                bitcoinConfirmationBlockLeaf,
                bitcoinConfirmationBlockSiblings,
                bitcoinConfirmationBlockPeaks,
                tipBlockHeight
            )
        ) revert Errors.InvalidConfirmationBlockInclusionProof();

        // [5] ensure the confirmation block delta is what the maker expects
        if (bitcoinConfirmationBlockLeaf.height != swapBlockHeight + swap.confirmationBlocks)
            revert Errors.InvalidConfirmationBlockDelta();

        // [6] ensure all utilized vaults hash to the aggregate vault commitment
        bytes32 aggregateVaultCommitmentHash = VaultLib.validateDepositVaultCommitment(utilizedVault, vaultCommitments);
        // [7] the aggregate vault commitment must be the same as when it was originally created
        if (aggregateVaultCommitmentHash != swap.aggregateVaultCommitment) revert Errors.InvalidVaultCommitment();

        // [8] empty deposit amount for utilized vault
        Types.DepositVault memory updatedVault = utilizedVault;
        updatedVault.depositAmount = 0;
        updatedVault.depositFee = 0;
        vaultCommitments[updatedVault.vaultIndex] = VaultLib.hashDepositVault(updatedVault);
        emit Events.VaultUpdated(updatedVault, Types.VaultUpdateContext.Release);

        // [9] update completed swap hash
        Types.ProposedSwap memory updatedSwap = swap;
        updatedSwap.state = Types.SwapState.Completed;
        bytes32 updatedSwapHash = VaultLib.hashSwap(updatedSwap);
        swapCommitments[swap.swapIndex] = updatedSwapHash;

        // [10] add protocol fee to accumulated fee balance
        accumulatedFeeBalance += swap.totalSwapFee;

        // [11] emit swap updated
        emit Events.SwapUpdated(updatedSwap, Types.SwapUpdateContext.Complete);

        // [12] release funds to buyers ETH payout address
        // TODO: Use a safe erc20 transfer library
        if (!DEPOSIT_TOKEN.transfer(swap.specifiedPayoutAddress, swap.totalSwapOutput)) revert Errors.TransferFailed();
    }

    //--------- READ FUNCTIONS ---------//

    function getVaultCommitmentsLength() public view returns (uint256) {
        return vaultCommitments.length;
    }

    function getSwapCommitmentsLength() public view returns (uint256) {
        return swapCommitments.length;
    }

    function getVaultCommitment(uint256 vaultIndex) public view returns (bytes32) {
        return vaultCommitments[vaultIndex];
    }

    function getSwapCommitment(uint256 swapIndex) public view returns (bytes32) {
        return swapCommitments[swapIndex];
    }
}
