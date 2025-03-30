// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";

contract ReactorFuzzTest is RiftTestSetup {
    function setUp() public override {
        super.setUp();
    }

    // --------------------------
    // Dutch Auction Properties
    // --------------------------

    /**
     * @notice Fuzz test that the auction sats calculation always returns a value
     * between minSats and maxSats (inclusive)
     * @param startBlock Start block for the auction
     * @param duration Duration of the auction
     * @param minSats Minimum sats value
     * @param maxSats Maximum sats value
     * @param blockOffset Offset from the startBlock to simulate different points in time
     */
    function testFuzz_ComputeAuctionSatsBounds(
        uint64 startBlock,
        uint64 duration,
        uint64 minSats,
        uint64 maxSats,
        uint64 blockOffset
    ) public {
        // Bound inputs to realistic values and prevent overflows
        vm.assume(startBlock < 10_000_000); // Reasonable block number
        vm.assume(duration > 0 && duration < 1_000_000); // Reasonable auction duration
        vm.assume(minSats < maxSats); // Ensure min is less than max
        vm.assume(maxSats < 1_000_000_000); // Reasonable max value
        vm.assume(blockOffset < 2_000_000); // Reasonable block offset

        // Additional safety check to prevent overflow
        vm.assume(startBlock + duration < type(uint64).max);
        vm.assume(startBlock + blockOffset < type(uint64).max);

        uint256 endBlock = startBlock + duration;

        // Create the auction info
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: minSats,
            maxSats: maxSats
        });

        // Set a block number for testing
        vm.roll(startBlock + blockOffset);

        // Compute auction sats
        uint256 computedSats = riftReactor.computeAuctionSats(auction);

        // Property: Result should always be between minSats and maxSats (inclusive)
        assertTrue(
            computedSats >= minSats && computedSats <= maxSats,
            "Computed sats should be between minSats and maxSats"
        );
    }

    /**
     * @notice Fuzz test that the auction sats calculation properly follows the linear decay model
     * @param startBlock Start block for the auction
     * @param duration Duration of the auction
     * @param minSats Minimum sats value
     * @param maxSats Maximum sats value
     */
    function testFuzz_ComputeAuctionSatsLinearDecay(
        uint64 startBlock,
        uint64 duration,
        uint64 minSats,
        uint64 maxSats
    ) public {
        // Bound inputs to realistic values and prevent overflows
        vm.assume(startBlock < 10_000_000); // Reasonable block number
        vm.assume(duration > 2 && duration < 1_000_000); // Reasonable auction duration
        vm.assume(minSats < maxSats); // Ensure min is less than max
        vm.assume(maxSats < 1_000_000_000); // Reasonable max value

        // Additional safety check to prevent overflow
        vm.assume(startBlock + duration < type(uint64).max);

        uint256 endBlock = startBlock + duration;

        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: minSats,
            maxSats: maxSats
        });

        // Check at auction start
        vm.roll(startBlock);
        uint256 startSats = riftReactor.computeAuctionSats(auction);
        assertEq(startSats, maxSats, "Should be maxSats at auction start");

        // Check at auction end
        vm.roll(endBlock);
        uint256 endSats = riftReactor.computeAuctionSats(auction);
        assertEq(endSats, minSats, "Should be minSats at auction end");

        // Check at auction midpoint
        uint256 midBlock = startBlock + (duration / 2);
        vm.roll(midBlock);
        uint256 midSats = riftReactor.computeAuctionSats(auction);

        // Calculate expected value at midpoint
        uint256 satsDifference = maxSats - minSats;
        uint256 expectedMidSats = maxSats - ((satsDifference * (midBlock - startBlock)) / duration);

        // Property: Value at midpoint should follow linear decay formula
        assertEq(midSats, expectedMidSats, "Midpoint should follow linear decay");
    }

    // --------------------------
    // Bond Calculation Properties
    // --------------------------

    /**
     * @notice Fuzz test that the bond calculation always returns at least MIN_BOND
     * @param depositAmount The deposit amount to calculate bond for
     */
    function testFuzz_ComputeBondMinimum(uint256 depositAmount) public view {
        // Limit deposit amount to prevent overflow in bond calculation
        vm.assume(depositAmount < type(uint128).max);

        uint96 bond = riftReactor.computeBond(depositAmount);
        uint96 minBond = riftReactor.MIN_BOND();

        // Property: Bond should always be at least MIN_BOND
        assert(bond >= minBond);
    }

    /**
     * @notice Fuzz test that the bond calculation correctly applies the BOND_BIPS
     * @param depositAmount The deposit amount to calculate bond for
     */
    function testFuzz_ComputeBondBips(uint256 depositAmount) public {
        // Limit deposit amount to prevent overflow in bond calculation
        vm.assume(depositAmount < type(uint96).max);

        uint96 bond = riftReactor.computeBond(depositAmount);
        uint96 minBond = riftReactor.MIN_BOND();
        uint16 bondBips = riftReactor.BOND_BIPS();
        uint96 maxBond = type(uint96).max;

        // Calculate expected bond (depositAmount * BOND_BIPS / 10000)
        uint256 calculatedBond = (depositAmount * bondBips) / 10000;

        // Property: If calculated bond is less than MIN_BOND, return MIN_BOND
        if (calculatedBond < minBond) {
            assertEq(bond, minBond, "Bond should be MIN_BOND when calculated bond is lower");
        }
        // Property: Otherwise, if it fits in uint96, return the calculated bond
        else if (calculatedBond <= type(uint96).max) {
            assertEq(bond, uint96(calculatedBond), "Bond should equal depositAmount * BOND_BIPS / 10000");
        }
        // Property: If calculated bond is too large for uint96, it should be capped at max
        else {
            assertEq(bond, maxBond, "Bond should be capped at uint96.max");
        }
    }

    /**
     * @notice Fuzz test to ensure the bond calculation always uses the correct formula
     * across a wide range of values
     * @param depositAmount The deposit amount to calculate bond for
     */
    function testFuzz_ComputeBondFormula(uint256 depositAmount) public {
        // Limit deposit amount to prevent overflow in bond calculation
        vm.assume(depositAmount < type(uint96).max);

        uint96 bond = riftReactor.computeBond(depositAmount);
        uint96 minBond = riftReactor.MIN_BOND();
        uint16 bondBips = riftReactor.BOND_BIPS();
        uint96 maxBond = type(uint96).max;

        // Manual calculation of the expected bond
        uint256 calculatedBond = (depositAmount * bondBips) / 10000;
        uint256 expectedBond;

        if (calculatedBond < minBond) {
            expectedBond = minBond;
        } else if (calculatedBond <= type(uint96).max) {
            expectedBond = calculatedBond;
        } else {
            expectedBond = maxBond;
        }

        // Property: Bond calculation should match our expected formula
        assertEq(bond, uint96(expectedBond), "Bond calculation should match expected formula");
    }
}
