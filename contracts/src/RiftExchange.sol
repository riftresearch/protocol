// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {UUPSUpgradeable} from "@openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/access/OwnableUpgradeable.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

import {BitcoinLightClientUpgradeable} from "./BitcoinLightClientUpgradeable.sol";

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
error InvalidBlockInclusionProof();
error CannotOverwriteOnGoingSwap();
error NoFeeToPay();
error InvalidVaultCommitment();
error StillInChallengePeriod();
error SwapNotProved();

// TODO: Make unnecessary public functions internal
/**
 * @title RiftExchange
 * @notice A decentralized exchange for cross-chain Bitcoin to ERC20 swaps
 * @dev Uses a Bitcoin light client and zero-knowledge proofs for verification
 */
contract RiftExchange is BitcoinLightClientUpgradeable, OwnableUpgradeable, UUPSUpgradeable {
    // --------- TYPES --------- //
    enum SwapState {
        None,
        Proved,
        Completed
    }

    struct DepositVault {
        uint256 vaultIndex;
        uint64 depositTimestamp;
        uint256 depositAmount;
        uint256 depositFee;
        uint64 expectedSats;
        bytes22 btcPayoutScriptPubKey;
        address specifiedPayoutAddress;
        address ownerAddress;
        bytes32 salt;
    }

    struct ProposedSwap {
        uint256 swapIndex;
        bytes32 aggregateVaultCommitment;
        BlockLeaf proposedBlockLeaf;
        uint64 liquidityUnlockTimestamp;
        address specifiedPayoutAddress;
        uint256 totalSwapFee;
        uint256 totalSwapAmount;
        SwapState state;
    }

    struct SwapProofPublicInputs {
        bytes32 proposedBlockHash;
        bytes32 aggregateVaultCommitment;
        bytes32 previousMmrRoot;
        bytes32 newMmrRoot;
        bytes32 compressedLeavesCommitment;
        uint256 proposedBlockCumulativeChainwork;
        address specifiedPayoutAddress;
        uint64 proposedBlockHeight;
        uint64 confirmationBlocks;
        uint256 totalSwapFee;
        uint256 totalSwapAmount;
    }

    // --------- CONSTANTS --------- //
    uint16 public constant DEPOSIT_LOCKUP_PERIOD = 8 hours;
    uint16 public constant MIN_OUTPUT_SATS = 1000; // to prevent dust errors
    // TODO: Challenge period should scale with the number of blocks in the proof.
    // Set it to 2x the estimated proof generation time for n blocks.
    uint32 public constant CHALLENGE_PERIOD = 5 minutes;
    uint32 public constant MIN_PROTOCOL_FEE = 100_000; // 10 cents USDC
    uint32 public constant MIN_DEPOSIT_AMOUNT = MIN_PROTOCOL_FEE + 1;
    uint8 public constant PROTOCOL_FEE_BP = 10; // maker + taker fee = 0.1%
    // Since upgradeable contracts cannot use immutable state variables,
    // we use constants instead to reduce gas costs (no SLOADs).
    // Note: This approach makes deployments more complex.
    /// @dev FOR BASE MAINNET DEPLOYMENT:
    IERC20 public constant DEPOSIT_TOKEN = IERC20(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913);
    uint8 public constant TOKEN_DECIMALS = 6;
    bytes32 public constant CIRCUIT_VERIFICATION_KEY =
        0x00334569e4b8059d7b1a70c011d7d92b5d3ce28f2148b32cd2396aeda3ae5af1;
    ISP1Verifier public constant VERIFIER_CONTRACT = ISP1Verifier(0x3B6041173B80E77f038f3F2C0f9744f04837185e);
    address public constant FEE_ROUTER_ADDRESS = 0xfEe8d79961c529E06233fbF64F96454c2656BFEE;
    uint8 public constant MIN_CONFIRMATION_BLOCKS = 3;

    // --------- STATE --------- //

    bytes32[] public vaultCommitments;
    bytes32[] public swapCommitments;
    uint256 public accumulatedFeeBalance;

    // --------- EVENTS --------- //

    event VaultUpdated(DepositVault vault);
    event SwapUpdated(ProposedSwap swap);

    //--------- CONSTRUCTOR ---------//
    function initialize(
        bytes32 _mmrRoot,
        BlockLeaf calldata _initialCheckpointLeaf,
        address initialOwner
    ) public initializer {
        __UUPSUpgradeable_init();
        __Ownable_init(initialOwner);
        __BitcoinLightClientUpgradeable_init(_mmrRoot, _initialCheckpointLeaf);
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    //--------- WRITE FUNCTIONS ---------//
    /// @notice Sends accumulated protocol fees to the fee router contract
    /// @dev Reverts if there are no fees to pay or if the transfer fails
    function payoutToFeeRouter() external {
        if (accumulatedFeeBalance == 0) revert NoFeeToPay();
        accumulatedFeeBalance = 0;
        if (!DEPOSIT_TOKEN.transfer(FEE_ROUTER_ADDRESS, accumulatedFeeBalance)) revert TransferFailed();
    }

    /// @notice Deposits new liquidity into a new vault
    /// @param specifiedPayoutAddress Address to receive swap proceeds
    /// @param initialDepositAmount Amount of ERC20 tokens to deposit including fee
    /// @param expectedSats Expected BTC output in satoshis
    /// @param btcPayoutScriptPubKey Bitcoin script for receiving BTC
    function depositLiquidity(
        address specifiedPayoutAddress,
        uint256 initialDepositAmount,
        uint64 expectedSats,
        bytes22 btcPayoutScriptPubKey
    ) external {
        // [0] create deposit liquidity request
        (DepositVault memory vault, bytes32 depositHash) = prepareDeposit(
            specifiedPayoutAddress,
            initialDepositAmount,
            expectedSats,
            btcPayoutScriptPubKey,
            vaultCommitments.length
        );

        // [1] add deposit hash to vault commitments
        vaultCommitments.push(depositHash);

        // [2] finalize deposit
        finalizeDeposit(vault);
    }

    /// @notice Deposits new liquidity by overwriting an existing empty vault
    /// @param overwriteVault Existing empty vault to overwrite
    /// @dev Identical to depositLiquidity, but allows for overwriting an existing empty vault
    function depositLiquidityWithOverwrite(
        address specifiedPayoutAddress,
        uint256 initialDepositAmount,
        uint64 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        DepositVault calldata overwriteVault
    ) external {
        // [0] create deposit liquidity request
        (DepositVault memory vault, bytes32 depositHash) = prepareDeposit(
            specifiedPayoutAddress,
            initialDepositAmount,
            expectedSats,
            btcPayoutScriptPubKey,
            overwriteVault.vaultIndex
        );

        // [1] ensure passed vault is real and overwritable
        validateDepositVaultCommitment(overwriteVault);
        if (overwriteVault.depositAmount != 0) revert DepositVaultNotOverwritable();

        // [2] overwrite deposit vault
        vaultCommitments[overwriteVault.vaultIndex] = depositHash;

        // [3] finalize deposit
        finalizeDeposit(vault);
    }

    /// @notice Checks invariants and creates new deposit vault struct
    /// @dev Validates deposit amounts and creates vault structure
    /// @return Tuple of the new vault and its commitment hash
    function prepareDeposit(
        address specifiedPayoutAddress,
        uint256 initialDepositAmount,
        uint64 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        uint256 depositVaultIndex
    ) public view returns (DepositVault memory, bytes32) {
        // [0] ensure deposit amount is greater than min protocol fee
        if (initialDepositAmount < MIN_DEPOSIT_AMOUNT) revert DepositAmountTooLow();

        // [1] ensure expected sat output is above minimum to prevent dust errors
        if (expectedSats < MIN_OUTPUT_SATS) revert SatOutputTooLow();

        // [2] ensure scriptPubKey is valid
        if (!validateP2WPKHScriptPubKey(btcPayoutScriptPubKey)) revert InvalidScriptPubKey();

        uint256 depositFee = calculateFeeFromAmount(initialDepositAmount);

        DepositVault memory vault = DepositVault({
            vaultIndex: depositVaultIndex,
            depositTimestamp: uint64(block.timestamp),
            depositAmount: initialDepositAmount - depositFee,
            depositFee: depositFee,
            expectedSats: expectedSats,
            btcPayoutScriptPubKey: btcPayoutScriptPubKey,
            specifiedPayoutAddress: specifiedPayoutAddress,
            ownerAddress: msg.sender,
            salt: EfficientHashLib.hash(
                bytes32(blockhash(block.number - 1)),
                bytes32(depositVaultIndex),
                bytes32(block.chainid)
            )
        });
        return (vault, hashDepositVault(vault));
    }

    /// @notice Completes deposit by emitting event and transferring tokens
    function finalizeDeposit(DepositVault memory vault) public {
        emit VaultUpdated(vault);
        if (!DEPOSIT_TOKEN.transferFrom(msg.sender, address(this), vault.depositAmount + vault.depositFee))
            revert TransferFailed();
    }

    /// @notice Withdraws liquidity from a deposit vault after the lockup period
    /// @param vault The deposit vault to withdraw from
    /// @dev Anyone can call, reverts if vault doesn't exist, is empty, or still in lockup period
    function withdrawLiquidity(DepositVault calldata vault) external {
        // [0] validate deposit vault exists
        validateDepositVaultCommitment(vault);

        // [1] ensure deposit amount is non-zero
        if (vault.depositAmount == 0) revert EmptyDepositVault();

        // [2] ensure the deposit vault is not time locked
        if (block.timestamp < vault.depositTimestamp + DEPOSIT_LOCKUP_PERIOD) revert DepositStillLocked();

        // [3] update deposit vault commitment
        DepositVault memory updatedVault = vault;
        updatedVault.depositAmount = 0;
        updatedVault.depositFee = 0;
        bytes32 updatedVaultHash = hashDepositVault(updatedVault);
        vaultCommitments[vault.vaultIndex] = updatedVaultHash;

        // [4] transfer funds to vault owner
        emit VaultUpdated(updatedVault);
        if (!DEPOSIT_TOKEN.transfer(vault.ownerAddress, vault.depositAmount)) {
            revert TransferFailed();
        }
    }

    /// @notice Internal function to prepare and validate a new swap
    /// @return swap The prepared swap struct
    /// @return updatedSwapHash The hash of the prepared swap
    function validateSwap(
        uint256 swapIndex,
        bytes32 proposedBlockHash,
        uint64 proposedBlockHeight,
        uint256 proposedBlockCumulativeChainwork,
        DepositVault[] calldata vaults,
        address specifiedPayoutAddress,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        uint256 totalSwapFee,
        uint256 totalSwapAmount,
        bytes calldata proof,
        bytes calldata compressedBlockLeaves
    ) public returns (ProposedSwap memory swap, bytes32 updatedSwapHash) {
        // [0] create deposit vault & compressed leaves commitments
        bytes32 aggregateVaultCommitment = validateDepositVaultCommitments(vaults);
        bytes32 compressedLeavesCommitment = EfficientHashLib.hash(compressedBlockLeaves);

        // [1] craft public inputs and verify proof
        bytes memory publicInputs = abi.encode(
            SwapProofPublicInputs({
                proposedBlockHash: proposedBlockHash,
                aggregateVaultCommitment: aggregateVaultCommitment,
                previousMmrRoot: priorMmrRoot,
                newMmrRoot: newMmrRoot,
                compressedLeavesCommitment: compressedLeavesCommitment,
                proposedBlockCumulativeChainwork: proposedBlockCumulativeChainwork,
                specifiedPayoutAddress: specifiedPayoutAddress,
                proposedBlockHeight: proposedBlockHeight,
                confirmationBlocks: MIN_CONFIRMATION_BLOCKS,
                totalSwapFee: totalSwapFee,
                totalSwapAmount: totalSwapAmount
            })
        );

        VERIFIER_CONTRACT.verifyProof(CIRCUIT_VERIFICATION_KEY, publicInputs, proof);
        updateRoot(priorMmrRoot, newMmrRoot);

        // [2] create the new swap
        swap = ProposedSwap({
            swapIndex: swapIndex,
            aggregateVaultCommitment: aggregateVaultCommitment,
            proposedBlockLeaf: BlockLeaf({
                blockHash: proposedBlockHash,
                height: proposedBlockHeight,
                cumulativeChainwork: proposedBlockCumulativeChainwork
            }),
            liquidityUnlockTimestamp: uint64(block.timestamp + CHALLENGE_PERIOD),
            specifiedPayoutAddress: specifiedPayoutAddress,
            totalSwapFee: totalSwapFee,
            totalSwapAmount: totalSwapAmount,
            state: SwapState.Proved
        });

        updatedSwapHash = hashSwap(swap);
    }

    /// @notice Submits a new swap proof and adds it to swapCommitments
    /// @param proposedBlockHash Hash of the Bitcoin block containing the swap
    /// @param proposedBlockHeight Height of the Bitcoin block
    /// @param proposedBlockCumulativeChainwork Cumulative chainwork up to this block
    /// @param vaults Array of deposit vaults being used in the swap
    /// @param specifiedPayoutAddress Address to receive the swap proceeds
    /// @param priorMmrRoot Previous MMR root used to generate this swap proof
    /// @param newMmrRoot Updated MMR root at least incluing up to the confirmation block
    /// @param proof ZK proof validating the swap
    /// @param compressedBlockLeaves Compressed block data for MMR Data Availability
    function submitSwapProof(
        bytes32 proposedBlockHash,
        uint64 proposedBlockHeight,
        uint256 proposedBlockCumulativeChainwork,
        DepositVault[] calldata vaults,
        address specifiedPayoutAddress,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        uint256 totalSwapFee,
        uint256 totalSwapAmount,
        bytes calldata proof,
        bytes calldata compressedBlockLeaves
    ) external {
        // [0] validate swap proof
        (ProposedSwap memory swap, bytes32 updatedSwapHash) = validateSwap(
            swapCommitments.length,
            proposedBlockHash,
            proposedBlockHeight,
            proposedBlockCumulativeChainwork,
            vaults,
            specifiedPayoutAddress,
            priorMmrRoot,
            newMmrRoot,
            totalSwapFee,
            totalSwapAmount,
            proof,
            compressedBlockLeaves
        );

        // [1] update swap commitments with updated swap hash
        swapCommitments.push(updatedSwapHash);
        emit SwapUpdated(swap);
    }

    /// @notice Same as submitSwapProof but overwrites an existing completed swap commitment
    /// @param overwriteSwap Existing completed swap to overwrite
    /// @dev All other parameters are identical to submitSwapProof
    function submitSwapProofWithOverwrite(
        bytes32 proposedBlockHash,
        uint64 proposedBlockHeight,
        uint256 proposedBlockCumulativeChainwork,
        DepositVault[] calldata vaults,
        address specifiedPayoutAddress,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        uint256 totalSwapFee,
        uint256 totalSwapAmount,
        bytes calldata proof,
        bytes calldata compressedBlockLeaves,
        ProposedSwap calldata overwriteSwap
    ) external {
        // [0] validate overwrite swap exists and is completed
        validateSwapCommitment(overwriteSwap);
        if (overwriteSwap.state != SwapState.Completed) revert CannotOverwriteOnGoingSwap();

        // [1] validate swap proof
        (ProposedSwap memory swap, bytes32 updatedSwapHash) = validateSwap(
            overwriteSwap.swapIndex,
            proposedBlockHash,
            proposedBlockHeight,
            proposedBlockCumulativeChainwork,
            vaults,
            specifiedPayoutAddress,
            priorMmrRoot,
            newMmrRoot,
            totalSwapFee,
            totalSwapAmount,
            proof,
            compressedBlockLeaves
        );

        // [2] update swap commitments with updated swap hash
        swapCommitments[overwriteSwap.swapIndex] = updatedSwapHash;
        emit SwapUpdated(swap);
    }

    function releaseLiquidity(
        ProposedSwap calldata swap,
        bytes32[] calldata bitcoinBlockInclusionProof,
        DepositVault[] calldata utilizedVaults
    ) external {
        // [0] validate swap exists
        validateSwapCommitment(swap);

        // [1] validate swap has been proved
        if (swap.state != SwapState.Proved) {
            revert SwapNotProved();
        }

        // [2] ensure challenge period has passed since proof submission
        if (block.timestamp < swap.liquidityUnlockTimestamp) {
            revert StillInChallengePeriod();
        }

        // [3] ensure swap block is still part of longest chain
        if (!proveBlockInclusion(swap.proposedBlockLeaf, bitcoinBlockInclusionProof))
            revert InvalidBlockInclusionProof();

        // [4] ensure all utilized vaults hash to the aggregate vault commitment
        bytes32 aggregateVaultCommitmentHash = validateDepositVaultCommitments(utilizedVaults);
        if (aggregateVaultCommitmentHash != swap.aggregateVaultCommitment) revert InvalidVaultCommitment();

        // [5] empty deposit amounts for all associated deposit vaults
        for (uint256 i = 0; i < utilizedVaults.length; i++) {
            DepositVault memory updatedVault = utilizedVaults[i];
            updatedVault.depositAmount = 0;
            updatedVault.depositFee = 0;
            vaultCommitments[updatedVault.vaultIndex] = hashDepositVault(updatedVault);
        }

        // [6] update completed swap hash
        ProposedSwap memory updatedSwap = swap;
        updatedSwap.state = SwapState.Completed;
        bytes32 updatedSwapHash = hashSwap(updatedSwap);
        swapCommitments[swap.swapIndex] = updatedSwapHash;

        // [7] add protocol fee to accumulated fee balance
        accumulatedFeeBalance += swap.totalSwapFee;

        // [8] emit swap updated
        emit SwapUpdated(updatedSwap);

        // [9] release funds to buyers ETH payout address
        if (!DEPOSIT_TOKEN.transfer(swap.specifiedPayoutAddress, swap.totalSwapAmount)) {
            revert TransferFailed();
        }
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

    //--------- INTERNAL FUNCTIONS ---------//

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function hashDepositVault(DepositVault memory vault) public pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(vault));
    }

    function hashSwap(ProposedSwap memory swap) public pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(swap));
    }

    /// @notice Validates that a scriptPubKey follows the P2WPKH format (OP_0(0x00) + OP_PUSHBYTES_20(0x14) + <20-byte-pubkey-hash>)
    function validateP2WPKHScriptPubKey(bytes22 scriptPubKey) public pure returns (bool) {
        return scriptPubKey[0] == 0x00 && scriptPubKey[1] == 0x14;
    }

    function validateDepositVaultCommitment(DepositVault calldata vault) public view returns (bytes32) {
        bytes32 vaultHash = hashDepositVault(vault);
        if (vaultHash != vaultCommitments[vault.vaultIndex]) {
            revert DepositVaultDoesNotExist();
        }
        return vaultHash;
    }

    function validateSwapCommitment(ProposedSwap calldata swap) public view returns (bytes32) {
        bytes32 swapHash = hashSwap(swap);
        if (swapHash != swapCommitments[swap.swapIndex]) {
            revert SwapDoesNotExist();
        }
        return swapHash;
    }

    function validateDepositVaultCommitments(DepositVault[] calldata vaults) public view returns (bytes32) {
        bytes32[] memory vaultHashes = new bytes32[](vaults.length);
        for (uint256 i = 0; i < vaults.length; i++) {
            vaultHashes[i] = validateDepositVaultCommitment(vaults[i]);
        }
        return EfficientHashLib.hash(vaultHashes);
    }

    /// @notice Calculates protocol fee for a given deposit amount
    /// @param amount The amount being deposited/swapped
    /// @return protocolFee The calculated protocol fee, either 0.1% or MIN_PROTOCOL_FEE, whichever is larger
    function calculateFeeFromAmount(uint256 amount) public pure returns (uint256 protocolFee) {
        // [0] return $0.1 or 0.1% of swap value, whatever is larger
        protocolFee = (amount * PROTOCOL_FEE_BP) / 10e3; // bpScale value
        if (protocolFee < MIN_PROTOCOL_FEE) protocolFee = MIN_PROTOCOL_FEE;
    }
}
