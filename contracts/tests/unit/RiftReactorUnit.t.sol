// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup} from "../utils/RiftTestSetup.t.sol";
import {RiftReactor} from "../../src/RiftReactor.sol";
import {Types} from "../../src/libraries/Types.sol";

/**
 * @title RiftReactorUnit
 * @notice This contract tests the helper functions of the RiftReactor.
 * It covers the following:
 *  - computeBond(): calculates the required bond based on deposit amounts.
 *  - computeAuctionSats(): computes the expected auction sats via linear interpolation.
 *  - depositBond() & _getBondPosted(): handles cbBTC bond deposits from market makers.
 *
 * Happy path tests ensure that the computed values match expectations.
 * Sad path tests check for proper reverts when conditions (like insufficient allowance or balance) are not met.
 */
contract RiftReactorUnit is RiftTestSetup {
    // Default auction parameters (for testing the auction pricing logic).
    uint256 constant DEFAULT_MAX_SATS = 10000;
    uint256 constant DEFAULT_MIN_SATS = 5000;

    // -----------------------------
    // Tests for computeBond()
    // -----------------------------

    /**
     * @notice Test that when the calculated bond is below the minimum,
     * the function returns MIN_BOND.
     */
    function testComputeBondBelowMinimum() public view {
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        // thresholdDeposit is the deposit amount that yields exactly MIN_BOND.
        uint256 thresholdDeposit = minBond * bondMultiplier;
        // Use an amount just below threshold to force the computed bond below minimum.
        uint256 depositAmount = thresholdDeposit - 1;
        uint96 bond = riftReactor.computeBond(depositAmount);
        assertEq(bond, minBond, "Bond should be set to MIN_BOND when calculated bond is lower");
    }

    /**
     * @notice Test that when the calculated bond (depositAmount / bondMultiplier)
     * is above the minimum, computeBond returns that computed value.
     */
    function testComputeBondAboveMinimum() public view {
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 thresholdDeposit = minBond * bondMultiplier;
        uint256 extra = 5_000_000;
        // Deposit amount greater than thresholdDeposit yields a computed bond above MIN_BOND.
        uint256 depositAmount = thresholdDeposit + extra;
        uint96 bond = riftReactor.computeBond(depositAmount);
        uint96 expectedBond = uint96(depositAmount / bondMultiplier);
        assertEq(bond, expectedBond, "Bond should equal depositAmount/bondMultiplier when that is above MIN_BOND");
    }

    /**
     * @notice Test the edge case where depositAmount is exactly the threshold.
     * The computed bond should equal MIN_BOND.
     */
    function testComputeBondEdgeCase() public view {
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 depositAmount = minBond * bondMultiplier;
        uint96 bond = riftReactor.computeBond(depositAmount);
        assertEq(bond, minBond, "Bond should exactly equal MIN_BOND at the edge case");
    }

    // -----------------------------
    // Tests for computeAuctionSats()
    // -----------------------------

    /**
     * @notice Test that before the auction starts (current block less than startBlock),
     * computeAuctionSats returns maxSats.
     */
    function testComputeAuctionSatsBeforeStart() public {
        vm.roll(200); // Set block.number to 200.
        uint256 current = block.number;
        uint256 startBlock = current + 10;
        uint256 endBlock = current + 100;
        Types.DutchAuctionInfo memory info = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: DEFAULT_MIN_SATS,
            maxSats: DEFAULT_MAX_SATS
        });
        uint256 sats = riftReactor.computeAuctionSats(info);
        assertEq(sats, DEFAULT_MAX_SATS, "Auction sats should equal maxSats before the auction start");
    }

    /**
     * @notice Test that after the auction has ended (current block greater than endBlock),
     * computeAuctionSats returns minSats.
     */
    function testComputeAuctionSatsAfterEnd() public {
        vm.roll(200); // Set block.number to 200.
        uint256 current = block.number;
        uint256 startBlock = current - 100;
        uint256 endBlock = current - 10;
        Types.DutchAuctionInfo memory info = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: DEFAULT_MIN_SATS,
            maxSats: DEFAULT_MAX_SATS
        });
        uint256 sats = riftReactor.computeAuctionSats(info);
        assertEq(sats, DEFAULT_MIN_SATS, "Auction sats should equal minSats after the auction end");
    }

    /**
     * @notice Test the linear interpolation of auction sats at the midpoint of the auction period.
     */
    function testComputeAuctionSatsMiddle() public {
        vm.roll(1000); // Set block.number to 1000.
        uint256 current = block.number;
        uint256 startBlock = current + 10;
        uint256 duration = 100;
        uint256 endBlock = startBlock + duration;
        Types.DutchAuctionInfo memory info = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: DEFAULT_MIN_SATS,
            maxSats: DEFAULT_MAX_SATS
        });
        uint256 middleBlock = startBlock + (duration / 2);
        vm.roll(middleBlock);
        // Calculate the expected reduction in sats.
        uint256 reduction = ((DEFAULT_MAX_SATS - DEFAULT_MIN_SATS) * (duration / 2)) / duration;
        uint256 expectedSats = DEFAULT_MAX_SATS - reduction;
        uint256 sats = riftReactor.computeAuctionSats(info);
        assertEq(sats, expectedSats, "Auction sats should be correctly interpolated at the midpoint");
    }

    // -----------------------------
    // Tests for Bond Management (depositBond & _getBondPosted)
    // -----------------------------

    /**
     * @notice Happy path: Test that depositBond successfully transfers cbBTC tokens
     * from the market maker and updates the mmBondDeposits mapping.
     */
    function testDepositBond() public {
        uint96 depositAmount = 1000;

        // Approve the RiftReactor contract to spend cbBTC tokens on behalf of msg.sender.
        cbBTC.approve(address(riftReactor), depositAmount);
        riftReactor.depositBond(depositAmount);

        // Verify that the mmBondDeposits mapping is updated correctly.
        uint96 bond = riftReactor.mmBondDeposits(address(this));
        assertEq(bond, depositAmount, "Bond deposit should increase mmBondDeposits by the deposited amount");
    }

    /**
     * @notice Happy path: Test multiple market makers depositing bond.
     * This simulates deposits from two different accounts.
     */
    function testMultipleDepositBond() public {
        uint96 depositAmount = 500;

        // Deposit from the default test account.
        cbBTC.approve(address(riftReactor), depositAmount);
        riftReactor.depositBond(depositAmount);

        // Simulate a deposit from a different market maker.
        address mm = address(0x123);
        // Mint cbBTC tokens to the simulated market maker so that they have sufficient balance.
        cbBTC.mint(mm, 1_000_000);

        vm.startPrank(mm);
        cbBTC.approve(address(riftReactor), depositAmount);
        riftReactor.depositBond(depositAmount);
        vm.stopPrank();

        // Verify that both accounts have the correct bond deposit recorded.
        uint96 bond1 = riftReactor.mmBondDeposits(address(this));
        uint96 bond2 = riftReactor.mmBondDeposits(mm);
        assertEq(bond1, depositAmount, "Bond deposit for default account should equal depositAmount");
        assertEq(bond2, depositAmount, "Bond deposit for mm account should equal depositAmount");
    }

    /**
     * @notice Sad path: Test that depositBond reverts when there is insufficient allowance.
     * Since we're using the standard cbBTC token, we rely on its native revert behavior.
     */
    function testDepositBondInsufficientAllowance() public {
        uint96 depositAmount = 1000;
        // Do not approve any cbBTC tokens.
        vm.expectRevert();
        riftReactor.depositBond(depositAmount);
    }

    /**
     * @notice Sad path: Test that depositBond reverts when the caller has insufficient cbBTC balance.
     * We simulate this by using an account that hasn't been minted any cbBTC.
     */
    function testDepositBondInsufficientBalance() public {
        uint96 depositAmount = 1000;
        address noBalanceAccount = address(0x456);
        vm.startPrank(noBalanceAccount);
        // Approve the contract even though the balance is 0.
        cbBTC.approve(address(riftReactor), depositAmount);
        vm.expectRevert();
        riftReactor.depositBond(depositAmount);
        vm.stopPrank();
    }
}
