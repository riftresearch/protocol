// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.28;

import {Vm} from "forge-std/src/Vm.sol";
import "../../src/interfaces/IBTCDutchAuctionHouse.sol";
import "../../src/interfaces/IRiftExchange.sol";
import {HelperTypes} from "../utils/HelperTypes.t.sol";

import {BTCDutchAuctionHouse} from "../../src/BTCDutchAuctionHouse.sol";
import {RiftTest} from "../utils/RiftTest.t.sol";
import {HashLib} from "../../src/libraries/HashLib.sol";
import {FeeLib} from "../../src/libraries/FeeLib.sol";
import {OrderValidationLib} from "../../src/libraries/OrderValidationLib.sol";

/// @title BTCDutchAuctionHouse fuzz‑tests (updated for v0.8.28 contracts)
/// @notice Exercises `startAuction` with fuzzed inputs and checks that
///         the contract correctly records the auction and transfers tokens.
contract BTCDutchAuctionHouseUnitTest is RiftTest {
    using HashLib for DutchAuction;

    function _extractSingleAuctionFromLogs(Vm.Log[] memory logs) internal pure returns (DutchAuction memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IBTCDutchAuctionHouse.AuctionUpdated.selector) {
                return abi.decode(logs[i].data, (DutchAuction));
            }
        }
        revert("Auction not found");
    }

    BTCDutchAuctionHouse internal auctionHouse;

    function setUp() public virtual override {
        super.setUp(); // deploy SyntheticBTC & verifier helpers from RiftTest

        // Use a fresh light‑client checkpoint for this instance
        HelperTypes.MMRProof memory initialProof = _generateFakeBlockMMRProofFFI(0);

        auctionHouse = new BTCDutchAuctionHouse({
            _mmrRoot: initialProof.mmrRoot,
            _syntheticBitcoin: address(syntheticBTC),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _takerFeeBips: 5,
            _tipBlockLeaf: initialProof.blockLeaf
        });
    }

    function _startAuctionWithAssertions(
        uint256 depositAmount,
        uint64 startBtcOut,
        uint64 endBtcOut,
        uint64 decayBlocks,
        uint64 deadlineOffset,
        address fillerWhitelistContract,
        uint8 confirmationBlocks
    )
        internal
        returns (
            DutchAuction memory auction,
            uint256 _depositAmount,
            BaseCreateOrderParams memory baseParams,
            HelperTypes.MMRProof memory mmrProof
        )
    {
        /* 1. Normalise / bound all fuzzed inputs, get mintable amount */
        (
            depositAmount,
            startBtcOut,
            endBtcOut,
            decayBlocks,
            deadlineOffset,
            confirmationBlocks
        ) = _normaliseAuctionInputs(
            depositAmount,
            startBtcOut,
            endBtcOut,
            decayBlocks,
            deadlineOffset,
            confirmationBlocks
        );

        /* 2. Give this test contract sBTC and approve the AuctionHouse */
        _mintAndApproveSyntheticBTC(depositAmount);

        /* 3. Create BaseCreateOrderParams + initial MMR proof in isolation */
        {
            (baseParams, mmrProof) = _prepareBaseParamsAndProof(depositAmount, confirmationBlocks);

            DutchAuctionParams memory auctionParams = DutchAuctionParams({
                startBtcOut: startBtcOut,
                endBtcOut: endBtcOut,
                decayBlocks: decayBlocks,
                deadline: uint64(block.timestamp) + deadlineOffset,
                fillerWhitelistContract: fillerWhitelistContract
            });

            /* 4. Call contract & capture emitted Auction */
            uint256 preBalance = syntheticBTC.balanceOf(address(this));
            uint256 startBlock = block.number;
            uint64 startTime = uint64(block.timestamp);

            vm.recordLogs();
            auctionHouse.startAuction(depositAmount, auctionParams, baseParams);
            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                auction = _extractSingleAuctionFromLogs(logs);
            }

            /* 5. Assert all invariants */
            _assertPostAuctionState(
                auction,
                depositAmount,
                auctionParams,
                baseParams,
                preBalance,
                startBlock,
                startTime
            );
        }

        _depositAmount = depositAmount; // returned
    }

    /*──────────────────────── helper functions (private) ──────────────────────*/

    /**
     * Bounds and sanitises every fuzzed parameter so they fall in legal ranges.
     */
    function _normaliseAuctionInputs(
        uint256 depositAmount,
        uint64 startBtcOut,
        uint64 endBtcOut,
        uint64 decayBlocks,
        uint64 deadlineOffset,
        uint8 confirmationBlocks
    ) private view returns (uint256, uint64, uint64, uint64, uint64, uint8) {
        decayBlocks = uint64(bound(decayBlocks, 1, 1_000_000));
        startBtcOut = uint64(bound(startBtcOut, OrderValidationLib.MIN_OUTPUT_SATS + 1, type(uint64).max));
        endBtcOut = uint64(bound(endBtcOut, OrderValidationLib.MIN_OUTPUT_SATS, startBtcOut - 1));
        confirmationBlocks = uint8(
            bound(confirmationBlocks, OrderValidationLib.MIN_CONFIRMATION_BLOCKS, type(uint8).max)
        );
        deadlineOffset = uint64(bound(deadlineOffset, 1 days, 30 days));

        uint256 minDeposit = FeeLib.calculateMinDepositAmount(auctionHouse.takerFeeBips());
        depositAmount = bound(depositAmount, minDeposit, type(uint64).max);

        return (depositAmount, startBtcOut, endBtcOut, decayBlocks, deadlineOffset, confirmationBlocks);
    }

    /** Mints `amount` sBTC to this contract and approves the AuctionHouse. */
    function _mintAndApproveSyntheticBTC(uint256 amount) private {
        syntheticBTC.mint(address(this), amount);
        syntheticBTC.approve(address(auctionHouse), amount);
    }

    /**
     * Creates BaseCreateOrderParams and the accompanying (fake) MMR proof.
     * Keeping them in a dedicated scope reduces live stack variables.
     */
    function _prepareBaseParamsAndProof(
        uint256 depositAmount,
        uint8 confirmationBlocks
    ) private returns (BaseCreateOrderParams memory baseParams, HelperTypes.MMRProof memory mmrProof) {
        mmrProof = _generateFakeBlockMMRProofFFI(0);

        baseParams = BaseCreateOrderParams({
            owner: address(this),
            bitcoinScriptPubKey: _generateBtcPayoutScriptPubKey(),
            salt: bytes32(uint256(keccak256(abi.encodePacked(block.timestamp, depositAmount)))),
            confirmationBlocks: confirmationBlocks,
            safeBlockLeaf: mmrProof.blockLeaf
        });
    }

    /**
     * Confirms token flows, hash storage, and emitted event correctness.
     */
    function _assertPostAuctionState(
        DutchAuction memory auction,
        uint256 depositAmount,
        DutchAuctionParams memory auctionParams,
        BaseCreateOrderParams memory baseParams,
        uint256 preBalance,
        uint256 startBlock,
        uint64 startTime
    ) private view {
        // [1] token flow
        assertEq(syntheticBTC.balanceOf(address(this)), 0);
        assertEq(syntheticBTC.balanceOf(address(auctionHouse)), depositAmount);

        // [2] hash stored
        bytes32 storedHash = auctionHouse.auctionHashes(0);
        assertTrue(storedHash != bytes32(0));

        // [3] recompute & compare
        DutchAuction memory expected = DutchAuction({
            index: 0,
            baseCreateOrderParams: baseParams,
            dutchAuctionParams: auctionParams,
            depositAmount: depositAmount,
            startBlock: startBlock,
            startTimestamp: startTime,
            state: DutchAuctionState.Created
        });

        assertEq(auction.hash(), expected.hash(), "emitted vs expected");
        assertEq(storedHash, expected.hash(), "storage vs expected");

        // [4] spent tokens check
        assertEq(preBalance - depositAmount, syntheticBTC.balanceOf(address(this)));
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
        uint64 startBtcOut,
        uint64 endBtcOut,
        uint64 decayBlocks,
        uint64 deadlineOffset,
        address fillerWhitelistContract,
        uint8 confirmationBlocks,
        uint /* fuzzSalt */
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
     * Fuzz‑tests `claimAuction` and verifies:
     *  1. Auction state transitions to Filled.
     *  2. Auction hash is updated correctly in storage.
     *  3. VaultsUpdated event is emitted (indicating internal _depositLiquidity call).
     */
    function testFuzz_claimAuction(
        uint256 depositAmount,
        uint64 startBtcOut,
        uint64 endBtcOut,
        uint64 decayBlocks,
        uint64 deadlineOffset,
        uint8 confirmationBlocks,
        uint fillBlockOffset, // Blocks to advance before filling
        address filler,
        uint /* fuzzSalt */
    ) public {
        address fillerWhitelistContract = address(0);
        // Start the auction using the helper
        (DutchAuction memory auction, , , HelperTypes.MMRProof memory startProof) = _startAuctionWithAssertions(
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
        HelperTypes.MMRProof memory fillProof = _generateFakeBlockMMRProofFFI(startProof.blockLeaf.height);

        // Snapshot state before fill
        uint256 preclaimAuctionHouseBalance = syntheticBTC.balanceOf(address(auctionHouse));
        vm.recordLogs();

        /* ── Act: Fill Auction ───────────────────────────────────── */
        vm.prank(filler);
        auctionHouse.claimAuction(auction, "", fillProof.siblings, fillProof.peaks);

        /* ── Asserts ─────────────────────────────────────────────── */
        Vm.Log[] memory logs = vm.getRecordedLogs();
        DutchAuction memory filledAuction = _extractSingleAuctionFromLogs(logs);

        // [1] State Transition
        assertEq(uint(filledAuction.state), uint(DutchAuctionState.Filled), "Auction state should be Filled");

        // [2] Hash Update
        bytes32 storedHash = auctionHouse.auctionHashes(auction.index);
        assertEq(storedHash, filledAuction.hash(), "Stored hash mismatch after fill");

        // [3] Internal _createOrder call check (via OrderUpdated event)
        Order memory order = _extractSingleOrderFromLogs(logs);
        assertEq(uint8(order.state), uint8(OrderState.Created), "Order should have been created");

        // [4] Token balance check (should remain unchanged as tokens are now in a vault)
        assertEq(
            syntheticBTC.balanceOf(address(auctionHouse)),
            preclaimAuctionHouseBalance,
            "Auction house balance changed unexpectedly on fill"
        );
    }
}
