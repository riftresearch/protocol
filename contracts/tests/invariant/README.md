# RiftReactor Invariant Tests

This directory contains invariant tests for the RiftReactor contract. Invariant tests verify that certain properties ("invariants") of the system hold true regardless of the sequence of operations performed.

## What are Invariant Tests?

Unlike unit tests that verify specific paths through the code, invariant tests focus on validating that fundamental properties are never violated, no matter what sequence of actions is taken. These tests use fuzz testing to randomly call functions and verify that the invariants hold after each call.

## Test Structure

The tests are organized into two main components:

1. `RiftReactorHandler`: A contract that manages the test state and provides functions to:

   - Create bonds
   - Release bonds
   - Penalize bonds
   - Track bond amounts
   - Manage order hashes
   - Track user nonces

2. `RiftReactorInvariantTest`: The main test contract that defines and verifies the invariants.

## Invariants Tested

### Bond Management

1. `invariant_TotalBondsEqualsSumOfIndividualBonds`

   - Verifies that the total bond amount in the contract equals the sum of individual bonds plus slashed fees
   - Ensures no bonds are lost or created out of thin air

2. `invariant_BondAmountNeverLessThanMinBond`

   - Ensures all bonds meet the minimum bond requirement
   - Critical for economic security of the protocol

3. `invariant_SlashedBondsCorrectlyTracked`
   - Verifies that slashed bonds are properly accounted for
   - Ensures the slashed fees never exceed total bonds created

### Auction Mechanics

1. `invariant_AuctionPriceWithinBounds`

   - Verifies that auction prices stay within min/max bounds
   - Ensures the Dutch auction mechanism works as intended

2. `invariant_AuctionPriceDecreasesOverTime`
   - Confirms that auction prices only decrease over time
   - Validates the core Dutch auction mechanism

### System Integrity

1. `invariant_SufficientCbBTCForBonds`

   - Ensures the contract always has enough cbBTC to cover active bonds
   - Critical for protocol solvency

2. `invariant_UniqueIntentNonces`
   - Verifies that intent nonces are unique and monotonically increasing
   - Prevents replay attacks

## Unit Tests

In addition to invariant tests, this folder includes some unit tests that verify specific behaviors:

1. `test_IntentsReturnMinSatsAfterEndBlock`

   - Verifies that auctions return minSats after their end block
   - Ensures predictable auction end behavior

2. `test_UniqueOrderHashes`
   - Verifies that order hashes cannot be reused
   - Critical for preventing duplicate orders

## Running the Tests

To run all invariant tests:

```bash
forge test --match-contract RiftReactorInvariantTest -vv
```

The tests use Foundry's invariant testing system, which will:

1. Randomly select and call functions from the handler
2. Check all invariants after each call
3. Run for a configurable number of iterations (default: 256)
4. Report any invariant violations found

## Adding New Invariant Tests

When adding new invariant tests:

1. Add any necessary state tracking to the `RiftReactorHandler`
2. Add the new invariant function to `RiftReactorInvariantTest`
3. Register any new handler functions in the `setUp` function
4. Document the new invariant in this README
