// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Vm} from "forge-std/src/Vm.sol";

import {BTCDutchAuctionHouse} from "../../src/BTCDutchAuctionHouse.sol";
import {RiftTest} from "../utils/RiftTest.sol";
import {Types} from "../../src/libraries/Types.sol";
import {HashLib} from "../../src/libraries/HashLib.sol";
import {FeeLib} from "../../src/libraries/FeeLib.sol";
import {Events} from "../../src/libraries/Events.sol";

/// @title BTCDutchAuctionHouse fuzz‑tests (updated for v0.8.28 contracts)
/// @notice Exercises `startAuction` with fuzzed inputs and checks that
///         the contract correctly records the auction and transfers tokens.
contract BTCDutchAuctionHouseUnitTest is RiftTest {
    using HashLib for Types.DutchAuction;

    /* ────────────────────────────────────────────────────────────── */
    /*                          Helpers                              */
    /* ────────────────────────────────────────────────────────────── */

    function _extractSingleAuctionFromLogs(Vm.Log[] memory logs) internal pure returns (Types.DutchAuction memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == Events.AuctionUpdated.selector) {
                return abi.decode(logs[i].data, (Types.DutchAuction));
            }
        }
        revert("Auction not found");
    }

    /* ────────────────────────────────────────────────────────────── */
    /*                            State                               */
    /* ────────────────────────────────────────────────────────────── */

    BTCDutchAuctionHouse internal auctionHouse;

    /* ────────────────────────────────────────────────────────────── */
    /*                             SET‑UP                             */
    /* ────────────────────────────────────────────────────────────── */

    function setUp() public virtual override {
        super.setUp(); // deploy mockToken & verifier helpers from RiftTest

        // Use a fresh light‑client checkpoint for this instance
        Types.MMRProof memory initialProof = _generateFakeBlockMMRProofFFI(0);

        auctionHouse = new BTCDutchAuctionHouse({
            _mmrRoot:               initialProof.mmrRoot,
            _depositToken:          address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier:              address(verifier),
            _feeRouter:             address(0xfee),
            _takerFeeBips:          5,
            _tipBlockLeaf:          initialProof.blockLeaf
        });
    }

    /* ────────────────────────────────────────────────────────────── */
    /*                           FUZZ TESTS                           */
    /* ────────────────────────────────────────────────────────────── */

    /// @notice Internal helper to start an auction and perform standard assertions.
    /// @return auction The created auction struct.
    /// @return _depositAmount The amount deposited.
    /// @return baseParams The base deposit parameters used.
    /// @return mmrProof The MMR proof used for the safe block leaf.
    function _startAuctionWithAssertions(
        uint256 depositAmount,
        uint64  startBtcOut,
        uint64  endBtcOut,
        uint64  decayBlocks,
        uint64  deadlineOffset,
        address fillerWhitelistContract,
        uint8   confirmationBlocks
    ) internal returns (
        Types.DutchAuction memory auction,
        uint256 _depositAmount,
        Types.BaseDepositLiquidityParams memory baseParams,
        Types.MMRProof memory mmrProof
    ) {
        /* ── Sanitize fuzzed inputs ─────────────────────────────── */
        decayBlocks = uint64(bound(decayBlocks, 1, 1_000_000));
        startBtcOut = uint64(bound(startBtcOut, auctionHouse.MIN_OUTPUT_SATS() + 1, type(uint64).max));
        endBtcOut = uint64(bound(endBtcOut, auctionHouse.MIN_OUTPUT_SATS(), startBtcOut - 1));

        confirmationBlocks = uint8(bound(
            confirmationBlocks,
            auctionHouse.MIN_CONFIRMATION_BLOCKS(),
            type(uint8).max
        ));

        deadlineOffset = uint64(bound(deadlineOffset, 1 days, 30 days));

        uint256 minDeposit = FeeLib.calculateMinDepositAmount(auctionHouse.takerFeeBips());
        depositAmount = bound(depositAmount, minDeposit, type(uint64).max);

        /* ── Prepare funds ───────────────────────────────────────── */
        mockToken.mint(address(this), depositAmount);
        mockToken.approve(address(auctionHouse), depositAmount);

        /* ── Prepare params ──────────────────────────────────────── */
        mmrProof = _generateFakeBlockMMRProofFFI(0);

        baseParams = Types.BaseDepositLiquidityParams({
            depositOwnerAddress:       address(this),
            btcPayoutScriptPubKey:     _generateBtcPayoutScriptPubKey(),
            depositSalt:               bytes32(uint256(keccak256(abi.encodePacked(block.timestamp, depositAmount)))),
            confirmationBlocks:        confirmationBlocks,
            safeBlockLeaf:             mmrProof.blockLeaf
        });

        Types.DutchAuctionParams memory auctionParams = Types.DutchAuctionParams({
            startBtcOut: startBtcOut,
            endBtcOut:   endBtcOut,
            decayBlocks: decayBlocks,
            deadline:    uint64(block.timestamp) + deadlineOffset,
            fillerWhitelistContract: fillerWhitelistContract
        });

        /* ── Snapshot pre‑state ──────────────────────────────────── */
        uint256 preBalance   = mockToken.balanceOf(address(this));
        uint256 startBlock   = block.number;
        uint64  startTime    = uint64(block.timestamp);

        vm.recordLogs();
        /* ── Act ─────────────────────────────────────────────────── */
        auctionHouse.startAuction(depositAmount, auctionParams, baseParams);

        /* ── Asserts ─────────────────────────────────────────────── */
        Types.DutchAuction memory emmittedAuction = _extractSingleAuctionFromLogs(vm.getRecordedLogs());

        // [1] Token transfer
        assertEq(mockToken.balanceOf(address(this)), 0, "Caller should have no tokens left");
        assertEq(mockToken.balanceOf(address(auctionHouse)), depositAmount, "Contract balance incorrect");

        // [2] Hash appended
        bytes32 storedHash = auctionHouse.auctionHashes(0);
        assertTrue(storedHash != bytes32(0), "Auction hash not stored");

        // [3] Hash correctness
        Types.DutchAuction memory expectedAuction = Types.DutchAuction({
            auctionIndex:       0,
            baseDepositParams:  baseParams,
            dutchAuctionParams: auctionParams,
            depositAmount:      depositAmount,
            startBlock:         startBlock,
            startTimestamp:     startTime,
            state:              Types.DutchAuctionState.Created
        });

        assertEq(emmittedAuction.hash(), expectedAuction.hash(), "Mismatched auction between emitted and expected");
        assertEq(storedHash, expectedAuction.hash(), "Mismatched auction hash between storage and expected/emitted");

        // [4] Ensure the user actually spent the tokens
        assertEq(preBalance - depositAmount, mockToken.balanceOf(address(this)), "Balance maths mismatch");

        // Return values
        auction = emmittedAuction; // Use the emitted auction as it's confirmed on-chain
        _depositAmount = depositAmount;
    }

    /**
     * Fuzz‑tests `startAuction` and verifies:
     *  1. Tokens move from the caller to the contract.
     *  2. A new auction hash is appended.
     *  3. The stored hash matches an off‑chain recomputation of the struct.
     *
     *  Updates:
     *  - Aligns with the new DutchAuctionParams field sizes (uint256).
     *  - Ensures `decayBlocks` is never zero (new contract validation).
     */
    function testFuzz_startAuction(
        uint256 depositAmount,
        uint64  startBtcOut,
        uint64  endBtcOut,
        uint64  decayBlocks,
        uint64  deadlineOffset,
        address fillerWhitelistContract,
        uint8   confirmationBlocks,
        uint    /* fuzzSalt */
    ) public {
        _startAuctionWithAssertions(
            depositAmount,
            startBtcOut,
            endBtcOut,
            decayBlocks,
            deadlineOffset,
            fillerWhitelistContract,
            confirmationBlocks
        );
    }

    /**
     * Fuzz‑tests `fillAuction` and verifies:
     *  1. Auction state transitions to Filled.
     *  2. Auction hash is updated correctly in storage.
     *  3. VaultsUpdated event is emitted (indicating internal _depositLiquidity call).
     */
    function testFuzz_fillAuction(
        uint256 depositAmount,
        uint64  startBtcOut,
        uint64  endBtcOut,
        uint64  decayBlocks,
        uint64  deadlineOffset,
        uint8   confirmationBlocks,
        uint    fillBlockOffset, // Blocks to advance before filling
        address filler,
        uint    /* fuzzSalt */
    ) public {
        address fillerWhitelistContract = address(0);
        // Start the auction using the helper
        (Types.DutchAuction memory auction, , , Types.MMRProof memory startProof) = 
            _startAuctionWithAssertions(
                depositAmount,
                startBtcOut,
                endBtcOut,
                decayBlocks,
                deadlineOffset,
                fillerWhitelistContract,
                confirmationBlocks
            );

        /* ── Sanitize filler inputs ─────────────────────────────── */
        fillBlockOffset = bound(fillBlockOffset, 1, decayBlocks > 1 ? decayBlocks - 1 : 1); // Ensure fill happens after start, before full decay

        /* ── Prepare for fill ────────────────────────────────────── */
        // Advance time/blocks
        vm.roll(block.number + fillBlockOffset);
        vm.warp(block.timestamp + fillBlockOffset * 12); // Advance time roughly

        // Ensure auction is not expired before filling
        if (block.timestamp >= auction.dutchAuctionParams.deadline) {
           vm.warp(auction.dutchAuctionParams.deadline - 1); // Warp just before deadline
        }

        // Generate MMR proof for the safe block leaf relative to the *current* (advanced) block state
        // This proves the original safe block leaf is still part of the canonical chain recognized by the light client.
        Types.MMRProof memory fillProof = _generateFakeBlockMMRProofFFI(startProof.blockLeaf.height);

        // Snapshot state before fill
        uint256 preFillAuctionHouseBalance = mockToken.balanceOf(address(auctionHouse));
        vm.recordLogs();

        /* ── Act: Fill Auction ───────────────────────────────────── */
        vm.prank(filler);
        auctionHouse.fillAuction(auction, "", fillProof.siblings, fillProof.peaks);

        /* ── Asserts ─────────────────────────────────────────────── */
        Vm.Log[] memory logs = vm.getRecordedLogs();
        Types.DutchAuction memory filledAuction = _extractSingleAuctionFromLogs(logs);

        // [1] State Transition
        assertEq(uint(filledAuction.state), uint(Types.DutchAuctionState.Filled), "Auction state should be Filled");

        // [2] Hash Update
        bytes32 storedHash = auctionHouse.auctionHashes(auction.auctionIndex);
        assertEq(storedHash, filledAuction.hash(), "Stored hash mismatch after fill");

        // [3] Internal _depositLiquidity call check (via VaultsUpdated event)
        bool foundVaultUpdate = false;
        for (uint i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == Events.VaultsUpdated.selector) {
                (Types.DepositVault[] memory vaults, Types.VaultUpdateContext context) = 
                    abi.decode(logs[i].data, (Types.DepositVault[], Types.VaultUpdateContext));
                assertEq(uint(context), uint(Types.VaultUpdateContext.Created), "Vault context should be Created");
                assertTrue(vaults.length > 0, "No vaults in VaultsUpdated event");
                foundVaultUpdate = true;
                break;
            }
        }
        assertTrue(foundVaultUpdate, "VaultsUpdated event not found after fillAuction");

        // [4] Token balance check (should remain unchanged as tokens are now in a vault)
        assertEq(mockToken.balanceOf(address(auctionHouse)), preFillAuctionHouseBalance, "Auction house balance changed unexpectedly on fill");
    }
}
