// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;
import {RiftTestSetup} from "../utils/RiftTestSetup.t.sol";
import {RiftReactor} from "../../src/RiftReactor.sol";

contract RiftReactorUnit is RiftTestSetup {
    // Define default auction parameters for clarity.
    uint256 constant DEFAULT_MAX_SATS = 10000;
    uint256 constant DEFAULT_MIN_SATS = 5000;

    // -----------------------------
    // Tests for computeBond()
    // -----------------------------

    /// @notice Test that computeBond returns MIN_BOND when depositAmount yields a bond below the minimum.
    function testComputeBondBelowMinimum() public view {
        // Bond is computed as (depositAmount * BOND_BIPS / 10_000).
        // For BOND_BIPS = 100, this simplifies to depositAmount / 100.
        // To force the computed bond to be below MIN_BOND, choose depositAmount such that:
        //   depositAmount < MIN_BOND * (10_000 / BOND_BIPS)
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 thresholdDeposit = minBond * bondMultiplier;

        uint256 depositAmount = thresholdDeposit - 1;
        uint96 bond = riftReactor.computeBondPulic(depositAmount);
        assertEq(bond, minBond, "Bond should be set to MIN_BOND when calculated bond is lower");
    }

    /// @notice Test that computeBond returns depositAmount/100 when that value is above MIN_BOND.
    function testComputeBondAboveMinimum() public view {
        // For a deposit amount above the threshold, the computed bond is depositAmount / bondMultiplier.
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 thresholdDeposit = minBond * bondMultiplier;

        // Choose depositAmount greater than thresholdDeposit by an extra delta.
        uint256 extra = 5_000_000;
        uint256 depositAmount = thresholdDeposit + extra;
        uint96 bond = riftReactor.computeBondPulic(depositAmount);
        uint96 expectedBond = uint96(depositAmount / bondMultiplier);
        assertEq(bond, expectedBond, "Bond should equal depositAmount/bondMultiplier when that is above MIN_BOND");
    }

    /// @notice Test the edge case where depositAmount / bondMultiplier equals exactly MIN_BOND.
    function testComputeBondEdgeCase() public view {
        // Set depositAmount exactly to thresholdDeposit.
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 depositAmount = minBond * bondMultiplier;

        uint96 bond = riftReactor.computeBondPulic(depositAmount);
        assertEq(bond, minBond, "Bond should exactly equal MIN_BOND at the edge case");
    }

    // -----------------------------
    // Tests for computeAuctionSats()
    // -----------------------------

    /// @notice Test that computeAuctionSats returns maxSats when current block is before startBlock.
    function testComputeAuctionSatsBeforeStart() public {
        // Roll to a known block number.
        vm.roll(200);
        uint256 current = block.number;
        // Set auction to start in 10 blocks and end in 100 blocks.
        uint256 startBlock = current + 10;
        uint256 endBlock = current + 100;

        RiftReactor.DutchAuctionInfo memory info = RiftReactor.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: DEFAULT_MIN_SATS,
            maxSats: DEFAULT_MAX_SATS
        });

        // Before the auction start, expect maxSats.
        uint256 sats = riftReactor.computeAuctionSatsPublic(info);
        assertEq(sats, DEFAULT_MAX_SATS, "Auction sats should equal maxSats before the auction start");
    }

    /// @notice Test that computeAuctionSats returns minSats when current block is after endBlock.
    function testComputeAuctionSatsAfterEnd() public {
        // Roll to a known block number.
        vm.roll(200);
        uint256 current = block.number;
        // Set auction to have ended in the past.
        uint256 startBlock = current - 100;
        uint256 endBlock = current - 10;

        RiftReactor.DutchAuctionInfo memory info = RiftReactor.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: DEFAULT_MIN_SATS,
            maxSats: DEFAULT_MAX_SATS
        });

        // After the auction end, expect minSats.
        uint256 sats = riftReactor.computeAuctionSatsPublic(info);
        assertEq(sats, DEFAULT_MIN_SATS, "Auction sats should equal minSats after the auction end");
    }

    /// @notice Test that computeAuctionSats returns the correctly interpolated value in the middle of the auction.
    function testComputeAuctionSatsMiddle() public {
        // Roll to a known block number.
        vm.roll(1000);
        uint256 current = block.number;
        // Set an auction period starting in 10 blocks.
        uint256 startBlock = current + 10;
        uint256 duration = 100;
        uint256 endBlock = startBlock + duration;

        RiftReactor.DutchAuctionInfo memory info = RiftReactor.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: DEFAULT_MIN_SATS,
            maxSats: DEFAULT_MAX_SATS
        });

        // Roll to the midpoint of the auction period.
        uint256 middleBlock = startBlock + (duration / 2);
        vm.roll(middleBlock);

        // Calculate expected value:
        // elapsed = duration/2, diff = (maxSats - minSats).
        // reduction = (maxSats - minSats) * (duration/2) / duration.
        uint256 reduction = ((DEFAULT_MAX_SATS - DEFAULT_MIN_SATS) * (duration / 2)) / duration;
        uint256 expectedSats = DEFAULT_MAX_SATS - reduction;
        uint256 sats = riftReactor.computeAuctionSatsPublic(info);
        assertEq(sats, expectedSats, "Auction sats should be correctly interpolated at the midpoint");
    }
}
