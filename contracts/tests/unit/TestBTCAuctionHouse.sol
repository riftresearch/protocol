// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Vm} from "forge-std/src/Vm.sol";

import {BTCDutchAuctionHouse} from "../../src/BTCAuctionHouse.sol";
import {RiftTest} from "../utils/RiftTest.sol";
import {Types} from "../../src/libraries/Types.sol";
import {HashLib} from "../../src/libraries/HashLib.sol";
import {FeeLib} from "../../src/libraries/FeeLib.sol";
import {Events} from "../../src/libraries/Events.sol";
/// @title BTCDutchAuctionHouse fuzz‑tests
/// @notice Exercises `startAuction` with fuzzed inputs and checks that
///         the contract correctly records the auction and transfers tokens.
contract BTCDutchAuctionHouseUnitTest is RiftTest {
    using HashLib for Types.DutchAuction;

    function _extractSingleAuctionFromLogs(Vm.Log[] memory logs) internal pure returns (Types.DutchAuction memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == Events.AuctionsUpdated.selector) {
                return abi.decode(logs[i].data, (Types.DutchAuction[]))[0];
            }
        }
        revert("Auction not found");
    }

    BTCDutchAuctionHouse internal auctionHouse;

    // ---------------------------------------------------------------------
    //                                SET‑UP
    // ---------------------------------------------------------------------
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

    // ---------------------------------------------------------------------
    //                               FUZZ TESTS
    // ---------------------------------------------------------------------

    /**
     * Fuzz‑tests `startAuction` and verifies:
     *  1. Tokens move from the caller to the contract.
     *  2. A new auction hash is appended.
     *  3. The stored hash matches an off‑chain recomputation of the struct.
     */
    function testFuzz_startAuction(
        uint256 depositAmount,
        uint64  startBtcOut,
        uint64  tickSize,
        uint64  ticks,
        uint64  deadlineOffset,
        uint8   confirmationBlocks,
        uint
    ) public {
        // ---------------- Bound & sanitise fuzzed inputs ---------------- //
        tickSize        = uint64(bound(tickSize, 1, type(uint16).max));
        startBtcOut     = uint64(bound(startBtcOut, tickSize + auctionHouse.MIN_OUTPUT_SATS(), type(uint64).max));
        uint64 maxTicks = startBtcOut / tickSize;
        maxTicks        = maxTicks == 0 ? 1 : maxTicks; // avoid div‑by‑0 later
        ticks           = uint64(bound(ticks, 1, maxTicks));

        confirmationBlocks = uint8(bound(
            confirmationBlocks,
            auctionHouse.MIN_CONFIRMATION_BLOCKS(),
            type(uint8).max
        ));

        deadlineOffset = uint64(bound(deadlineOffset, 2 days, 30 days));

        uint256 minDeposit = FeeLib.calculateMinDepositAmount(auctionHouse.takerFeeBips());
        depositAmount = bound(depositAmount, minDeposit, type(uint64).max); // keep values small for speed

        // ------------------------ Prepare funds ------------------------ //
        mockToken.mint(address(this), depositAmount);
        mockToken.approve(address(auctionHouse), depositAmount);

        // ----------------------- Prepare params ------------------------ //
        Types.MMRProof memory mmrProof = _generateFakeBlockMMRProofFFI(0);

        Types.BaseDepositLiquidityParams memory baseParams = Types.BaseDepositLiquidityParams({
            depositOwnerAddress:       address(this),
            btcPayoutScriptPubKey:     _generateBtcPayoutScriptPubKey(),
            depositSalt:               bytes32(uint256(keccak256(abi.encodePacked(block.timestamp, depositAmount)))),
            confirmationBlocks:        confirmationBlocks,
            safeBlockLeaf:             mmrProof.blockLeaf
        });

        Types.DutchAuctionParams memory auctionParams = Types.DutchAuctionParams({
            startBtcOut: startBtcOut,
            tickSize:    tickSize,
            ticks:       ticks,
            deadline:    uint64(block.timestamp) + deadlineOffset
        });

        // -------------------- Snapshot pre‑state ----------------------- //
        uint256 preBalance   = mockToken.balanceOf(address(this));
        uint256 startBlock   = block.number;
        uint64  startTime    = uint64(block.timestamp);


        vm.recordLogs();
        // --------------------------- Act ------------------------------- //
        auctionHouse.startAuction(depositAmount, auctionParams, baseParams);

        // ------------------------- Asserts ----------------------------- //

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

        assertEq(
            storedHash,
            expectedAuction.hash(),
            "Mismatched auction hash between storage and expected/emitted"
        );

        // [4] Ensure the user actually spent the tokens
        assertEq(preBalance - depositAmount, mockToken.balanceOf(address(this)), "Balance maths mismatch");
    }
}
