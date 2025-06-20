// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BitcoinScriptLib} from "src/libraries/BitcoinScriptLib.sol";
import {HashLib} from "src/libraries/HashLib.sol";
import {FeeLib} from "src/libraries/FeeLib.sol";
import {ChallengePeriodLib} from "src/libraries/ChallengePeriodLib.sol";
import {DutchDecayLib} from "src/libraries/DutchDecayLib.sol";
import {MMRProofLib} from "src/libraries/MMRProof.sol";
import {OrderValidationLib} from "src/libraries/OrderValidationLib.sol";
import {Order, Payment} from "src/interfaces/IRiftExchange.sol";
import {BlockLeaf} from "src/interfaces/IBitcoinLightClient.sol";
import {DutchAuction} from "src/interfaces/IBTCDutchAuctionHouse.sol";
import {OrderLockupLib} from "src/libraries/OrderLockupLib.sol";

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
    //                              CHALLENGE PERIOD CALCULATIONS
    // =============================================================================
    
    
    /// @notice Calculates challenge period for elapsed bitcoin blocks
    /// @param blocksElapsed Number of elapsed bitcoin blocks
    /// @param blockFinalityTime finality time of the the chain the contract is deployed on
    /// @return challengePeriod The challenge period in seconds
    function calculateChallengePeriod(uint64 blocksElapsed, uint64 blockFinalityTime) public pure returns (uint256 challengePeriod) {
        return ChallengePeriodLib.calculateChallengePeriod(blocksElapsed, blockFinalityTime);
    }


    /// @notice Calculates lockup period for a given number of confirmations
    /// @param confirmations Number of confirmations
    /// @param blockFinalityTime finality time of the the chain the contract is deployed on
    /// @return lockupPeriod The lockup period in seconds
    function calculateLockupPeriod(uint8 confirmations, uint64 blockFinalityTime) public pure returns (uint64) {
        return OrderLockupLib.calculateLockupPeriod(confirmations, blockFinalityTime);
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