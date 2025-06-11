// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BitcoinScriptLib} from "src/libraries/BitcoinScriptLib.sol";
import {HashLib} from "src/libraries/HashLib.sol";
import {FeeLib} from "src/libraries/FeeLib.sol";
import {PeriodLib} from "src/libraries/PeriodLib.sol";
import {DutchDecayLib} from "src/libraries/DutchDecayLib.sol";
import {MMRProofLib} from "src/libraries/MMRProof.sol";
import {OrderValidationLib} from "src/libraries/OrderValidationLib.sol";
import {Order, Payment} from "src/interfaces/IRiftExchange.sol";
import {BlockLeaf} from "src/interfaces/IBitcoinLightClient.sol";
import {DutchAuction} from "src/interfaces/IBTCDutchAuctionHouse.sol";

contract LibExposer {
    // =============================================================================
    //                              BITCOIN SCRIPT UTILITIES
    // =============================================================================
    
    /// @notice Validates if a scriptPubKey is one of the supported Bitcoin address types
    /// @param scriptPubKey The Bitcoin scriptPubKey to validate
    /// @return bool True if valid P2PKH, P2SH, P2WPKH, P2WSH (v0), or P2TR (v1)
    function validateScriptPubKey(bytes memory scriptPubKey) public pure returns (bool) {
        return BitcoinScriptLib.validateScriptPubKey(scriptPubKey);
    }
    
    // =============================================================================
    //                              HASH UTILITIES
    // =============================================================================
    
    /// @notice Computes hash of an Order struct
    /// @param order The order to hash
    /// @return bytes32 The computed hash
    function hashOrder(Order memory order) public pure returns (bytes32) {
        return HashLib.hash(order);
    }
    
    /// @notice Computes hash of a Payment struct
    /// @param payment The payment to hash
    /// @return bytes32 The computed hash
    function hashPayment(Payment memory payment) public pure returns (bytes32) {
        return HashLib.hash(payment);
    }
    
    /// @notice Computes hash of a BlockLeaf struct
    /// @param blockLeaf The block leaf to hash
    /// @return bytes32 The computed hash
    function hashBlockLeaf(BlockLeaf memory blockLeaf) public pure returns (bytes32) {
        return HashLib.hash(blockLeaf);
    }
    
    /// @notice Computes hash of a DutchAuction struct
    /// @param dutchAuction The dutch auction to hash
    /// @return bytes32 The computed hash
    function hashDutchAuction(DutchAuction memory dutchAuction) public pure returns (bytes32) {
        return HashLib.hash(dutchAuction);
    }
    
    // =============================================================================
    //                              FEE CALCULATIONS
    // =============================================================================
    
    /// @notice Calculates minimum deposit amount for a given taker fee
    /// @param takerFeeBips Taker fee in basis points
    /// @return minDepositAmount The minimum deposit amount
    function calculateMinDepositAmount(uint16 takerFeeBips) public pure returns (uint256 minDepositAmount) {
        return FeeLib.calculateMinDepositAmount(takerFeeBips);
    }
    
    /// @notice Calculates protocol fee for a given deposit amount
    /// @param amount The deposit amount
    /// @param takerFeeBips Taker fee in basis points
    /// @return protocolFee The calculated protocol fee
    function calculateFeeFromDeposit(uint256 amount, uint16 takerFeeBips) public pure returns (uint256 protocolFee) {
        return FeeLib.calculateFeeFromDeposit(amount, takerFeeBips);
    }
    
    // =============================================================================
    //                              PERIOD CALCULATIONS
    // =============================================================================
    
    /// @notice Gets the deposit lockup period scalar constant
    /// @return uint32 The deposit lockup period scalar (2 hours)
    function getDepositLockupPeriodScalar() public pure returns (uint32) {
        return PeriodLib.DEPOSIT_LOCKUP_PERIOD_SCALAR;
    }
    
    /// @notice Gets the challenge period buffer constant
    /// @return uint32 The challenge period buffer (5 minutes)
    function getChallengePeriodBuffer() public pure returns (uint32) {
        return PeriodLib.CHALLENGE_PERIOD_BUFFER;
    }
    
    /// @notice Gets the scaled proof generation slope constant
    /// @return uint32 The scaled proof generation slope
    function getScaledProofGenSlope() public pure returns (uint32) {
        return PeriodLib.SCALED_PROOF_GEN_SLOPE;
    }
    
    /// @notice Gets the scaled proof generation intercept constant
    /// @return uint32 The scaled proof generation intercept
    function getScaledProofGenIntercept() public pure returns (uint32) {
        return PeriodLib.SCALED_PROOF_GEN_INTERCEPT;
    }
    
    /// @notice Gets the proof generation scaling factor constant
    /// @return uint32 The proof generation scaling factor
    function getProofGenScalingFactor() public pure returns (uint32) {
        return PeriodLib.PROOF_GEN_SCALING_FACTOR;
    }
    
    /// @notice Calculates challenge period for elapsed bitcoin blocks
    /// @param blocksElapsed Number of elapsed bitcoin blocks
    /// @return challengePeriod The challenge period in seconds
    function calculateChallengePeriod(uint64 blocksElapsed) public pure returns (uint256 challengePeriod) {
        return PeriodLib.calculateChallengePeriod(blocksElapsed);
    }
    
    /// @notice Calculates deposit lockup period for confirmations
    /// @param confirmations Number of confirmations required
    /// @return depositLockupPeriod The deposit lockup period in seconds
    function calculateDepositLockupPeriod(uint8 confirmations) public pure returns (uint64 depositLockupPeriod) {
        return PeriodLib.calculateDepositLockupPeriod(confirmations);
    }
    
    // =============================================================================
    //                              DUTCH DECAY CALCULATIONS
    // =============================================================================
    
    /// @notice Calculates linear decay between two points (uint256 version)
    /// @param startPoint Start of the decay
    /// @param endPoint End of the decay
    /// @param currentPoint Current position in the decay
    /// @param startAmount Start amount
    /// @param endAmount End amount
    /// @return uint256 The linearly interpolated amount
    function linearDecayUint(
        uint256 startPoint,
        uint256 endPoint,
        uint256 currentPoint,
        uint256 startAmount,
        uint256 endAmount
    ) public pure returns (uint256) {
        return DutchDecayLib.linearDecay(startPoint, endPoint, currentPoint, startAmount, endAmount);
    }
    
    /// @notice Calculates linear decay between two points (int256 version)
    /// @param startPoint Start of the decay
    /// @param endPoint End of the decay
    /// @param currentPoint Current position in the decay
    /// @param startAmount Start amount
    /// @param endAmount End amount
    /// @return int256 The linearly interpolated amount
    function linearDecayInt(
        uint256 startPoint,
        uint256 endPoint,
        uint256 currentPoint,
        int256 startAmount,
        int256 endAmount
    ) public pure returns (int256) {
        return DutchDecayLib.linearDecay(startPoint, endPoint, currentPoint, startAmount, endAmount);
    }
    
    // =============================================================================
    //                              MMR PROOF VERIFICATION
    // =============================================================================
    
    /// @notice Verifies an MMR inclusion proof
    /// @param leafHash Hash of the leaf to verify
    /// @param leafIndex Index of the leaf
    /// @param siblings Sibling hashes for the proof path
    /// @param peaks Array of MMR peaks
    /// @param leafCount Total number of leaves in the MMR
    /// @param mmrRoot Expected MMR root
    /// @return bool True if the proof is valid
    function verifyMMRProof(
        bytes32 leafHash,
        uint256 leafIndex,
        bytes32[] memory siblings,
        bytes32[] memory peaks,
        uint32 leafCount,
        bytes32 mmrRoot
    ) public pure returns (bool) {
        return MMRProofLib.verifyProof(leafHash, leafIndex, siblings, peaks, leafCount, mmrRoot);
    }
    
    /// @notice Bags (folds) peaks in right-to-left order
    /// @param peaks Array of peak hashes
    /// @return bytes32 The bagged peaks hash
    function bagPeaks(bytes32[] memory peaks) public pure returns (bytes32) {
        return MMRProofLib.bagPeaks(peaks);
    }
    
    // =============================================================================
    //                              ORDER VALIDATION CONSTANTS
    // =============================================================================
    
    /// @notice Gets the minimum output sats constant
    /// @return uint16 The minimum output sats (1000)
    function getMinOutputSats() public pure returns (uint16) {
        return OrderValidationLib.MIN_OUTPUT_SATS;
    }
    
    /// @notice Gets the minimum confirmation blocks constant
    /// @return uint8 The minimum confirmation blocks (2)
    function getMinConfirmationBlocks() public pure returns (uint8) {
        return OrderValidationLib.MIN_CONFIRMATION_BLOCKS;
    }
    


}