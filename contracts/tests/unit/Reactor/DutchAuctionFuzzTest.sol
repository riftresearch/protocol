// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";

contract DutchAuctionFuzzTest is RiftTestSetup {
    // Define block number range limits to prevent overflows or unreasonable values
    uint256 constant MAX_BLOCK_NUMBER = 10_000_000;

    function setUp() public override {
        super.setUp();
    }

    /**
     * @notice Fuzz test the computeAuctionSats function with a wide range of inputs
     * @param startBlock The auction start block
     * @param endBlock The auction end block
     * @param minSats The minimum satoshi amount
     * @param maxSats The maximum satoshi amount
     * @param currentBlock The current block number to test with
     */
    function testFuzz_ComputeAuctionSats(
        uint256 startBlock,
        uint256 endBlock,
        uint256 minSats,
        uint256 maxSats,
        uint256 currentBlock
    ) public {
        // Bound inputs to reasonable values to prevent overflows
        startBlock = bound(startBlock, 0, MAX_BLOCK_NUMBER);
        endBlock = bound(endBlock, startBlock, MAX_BLOCK_NUMBER); // Ensure endBlock >= startBlock
        minSats = bound(minSats, 0, type(uint64).max); // Use uint64 limit since expectedSats is uint64 in deposit params
        maxSats = bound(maxSats, minSats, type(uint64).max); // Ensure maxSats >= minSats
        currentBlock = bound(currentBlock, 0, MAX_BLOCK_NUMBER);

        // Create the auction info
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: minSats,
            maxSats: maxSats
        });

        // Set the current block number
        vm.roll(currentBlock);

        // Compute the expected sats for this auction at the current block
        uint256 expectedSats = riftReactor.computeAuctionSats(auction);

        // Verify that the result is within bounds
        assertTrue(expectedSats >= minSats, "Expected sats should be >= minSats");
        assertTrue(expectedSats <= maxSats, "Expected sats should be <= maxSats");

        // Check edge cases
        if (currentBlock <= startBlock) {
            assertEq(expectedSats, maxSats, "Should return maxSats before auction starts");
        } else if (currentBlock >= endBlock) {
            assertEq(expectedSats, minSats, "Should return minSats after auction ends");
        } else if (startBlock == endBlock) {
            // Handle zero-duration auctions
            assertEq(expectedSats, minSats, "Zero-duration auctions should return minSats at any time after start");
        } else {
            // For blocks during the auction, verify the linear decay formula
            // elapsed = currentBlock - startBlock
            // duration = endBlock - startBlock
            // expectedSats = maxSats - ((maxSats - minSats) * elapsed / duration)
            uint256 elapsed = currentBlock - startBlock;
            uint256 duration = endBlock - startBlock;
            uint256 diff = maxSats - minSats;
            uint256 reduction = (diff * elapsed) / duration;
            uint256 calculatedSats = maxSats - reduction;

            assertEq(expectedSats, calculatedSats, "Calculated sats does not match expected sats");
        }
    }

    /**
     * @notice Test that sats never increase as blocks progress
     * @param startBlock Auction start block
     * @param blockDuration Duration in blocks
     * @param minSats Minimum satoshis
     * @param maxSatsDelta Additional amount to add to minSats for maxSats
     */
    function testFuzz_AuctionNeverIncreases(
        uint64 startBlock,
        uint64 blockDuration,
        uint64 minSats,
        uint64 maxSatsDelta
    ) public {
        // Bound inputs to reasonable values
        startBlock = uint64(bound(startBlock, 0, MAX_BLOCK_NUMBER));
        blockDuration = uint64(bound(blockDuration, 0, 1000)); // Keep duration reasonable
        minSats = uint64(bound(minSats, 0, type(uint64).max / 2)); // Prevent overflow
        maxSatsDelta = uint64(bound(maxSatsDelta, 0, type(uint64).max / 2)); // Prevent overflow

        // Create auction with safe values
        uint64 endBlock = startBlock + blockDuration;
        uint64 maxSats = minSats + maxSatsDelta;

        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: minSats,
            maxSats: maxSats
        });

        // For auctions with equal min and max, the price remains constant
        if (minSats == maxSats || startBlock == endBlock) {
            return; // Skip constant-price auctions or zero-length auctions
        }

        // Set up testing for progressive blocks
        uint256 blockStep = blockDuration > 10 ? blockDuration / 10 : 1;

        uint256 lastSats = type(uint256).max; // Starting with max to ensure comparison works

        // Test across the auction duration
        for (uint256 block = startBlock; block <= endBlock + 10; block += blockStep) {
            vm.roll(block);
            uint256 currentSats = riftReactor.computeAuctionSats(auction);

            if (lastSats != type(uint256).max) {
                assertTrue(currentSats <= lastSats, "Sats should never increase as blocks progress");
            }

            lastSats = currentSats;
        }
    }

    /**
     * @notice Test the handling of edge cases in the auction mechanism
     */
    function test_AuctionEdgeCases() public {
        // Test 1: Zero duration auction (startBlock = endBlock)
        Types.DutchAuctionInfo memory zeroDurationAuction = Types.DutchAuctionInfo({
            startBlock: 100,
            endBlock: 100,
            minSats: 1000,
            maxSats: 2000
        });

        // Before auction
        vm.roll(99);
        assertEq(
            riftReactor.computeAuctionSats(zeroDurationAuction),
            zeroDurationAuction.maxSats,
            "Before zero-duration auction: should return maxSats"
        );

        // At auction boundary
        vm.roll(100);
        assertEq(
            riftReactor.computeAuctionSats(zeroDurationAuction),
            zeroDurationAuction.minSats,
            "At zero-duration auction boundary: should return minSats"
        );

        // After auction
        vm.roll(101);
        assertEq(
            riftReactor.computeAuctionSats(zeroDurationAuction),
            zeroDurationAuction.minSats,
            "After zero-duration auction: should return minSats"
        );

        // Test 2: Zero difference auction (minSats = maxSats)
        Types.DutchAuctionInfo memory constantPriceAuction = Types.DutchAuctionInfo({
            startBlock: 100,
            endBlock: 200,
            minSats: 1000,
            maxSats: 1000
        });

        // Before auction
        vm.roll(99);
        assertEq(
            riftReactor.computeAuctionSats(constantPriceAuction),
            constantPriceAuction.maxSats,
            "Before constant-price auction: should return maxSats"
        );

        // During auction
        vm.roll(150);
        assertEq(
            riftReactor.computeAuctionSats(constantPriceAuction),
            constantPriceAuction.minSats,
            "During constant-price auction: should return constant price"
        );

        // After auction
        vm.roll(201);
        assertEq(
            riftReactor.computeAuctionSats(constantPriceAuction),
            constantPriceAuction.minSats,
            "After constant-price auction: should return minSats"
        );

        // Test 3: One block duration auction
        Types.DutchAuctionInfo memory oneBlockAuction = Types.DutchAuctionInfo({
            startBlock: 100,
            endBlock: 101,
            minSats: 1000,
            maxSats: 2000
        });

        // Before auction
        vm.roll(99);
        assertEq(
            riftReactor.computeAuctionSats(oneBlockAuction),
            oneBlockAuction.maxSats,
            "Before one-block auction: should return maxSats"
        );

        // At start block
        vm.roll(100);
        assertEq(
            riftReactor.computeAuctionSats(oneBlockAuction),
            oneBlockAuction.maxSats,
            "At one-block auction start: should return maxSats"
        );

        // At end block
        vm.roll(101);
        assertEq(
            riftReactor.computeAuctionSats(oneBlockAuction),
            oneBlockAuction.minSats,
            "At one-block auction end: should return minSats"
        );

        // After auction
        vm.roll(102);
        assertEq(
            riftReactor.computeAuctionSats(oneBlockAuction),
            oneBlockAuction.minSats,
            "After one-block auction: should return minSats"
        );
    }

    /**
     * @notice Test the linear decay pattern of the auction across its duration
     */
    function test_AuctionLinearDecay() public {
        // Create a 100-block auction with a 1000 sat difference
        uint256 startBlock = 100;
        uint256 endBlock = 200;
        uint256 minSats = 1000;
        uint256 maxSats = 2000;
        uint256 duration = endBlock - startBlock;
        uint256 diff = maxSats - minSats;

        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: minSats,
            maxSats: maxSats
        });

        // Test at 10% intervals through the auction
        for (uint256 i = 0; i <= 10; i++) {
            uint256 currentBlock = startBlock + (duration * i) / 10;
            vm.roll(currentBlock);

            uint256 expectedReduction = (diff * i) / 10;
            uint256 expectedSats = maxSats - expectedReduction;

            uint256 actualSats = riftReactor.computeAuctionSats(auction);

            assertEq(actualSats, expectedSats, "Auction decay should be linear at each 10% interval");
        }
    }
}
