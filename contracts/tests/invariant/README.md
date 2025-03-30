# Invariant Testing for RiftReactor

This directory contains invariant tests for the RiftReactor contract. These tests verify that critical system properties hold true regardless of the sequence or combination of operations performed.

## What are Invariant Tests?

Invariant tests ensure that certain properties of the system remain true ("invariant") regardless of the inputs or state transitions. Unlike unit tests that verify specific paths through the code, invariant tests focus on validating that fundamental properties are never violated.

## RiftReactor Invariants

The following invariants are tested in `RiftReactorInvariants.t.sol`:

1. **Bond Accounting Correctness** - The total number of bonds created must always be greater than or equal to the sum of bonds released and penalized.

2. **Minimum Bond Amount** - All active bonds must be at least the `MIN_BOND` amount.

3. **Slashed Fees Persistence** - The accumulated fees from penalized bonds must match the `slashedBondFees` tracked in the contract.

## Testing Approach

The invariant tests use a handler contract (`RiftReactorHandler`) that exposes a set of actions that can be performed on the RiftReactor:

- `createBond()` - Creates a new bonded swap with random parameters
- `releaseBond()` - Releases a bond, simulating successful swap execution
- `penalizeBond()` - Penalizes a bond, simulating a failed/abandoned swap

Foundry's StdInvariant fuzzing engine then randomly calls these functions in various sequences and validates that our invariants hold after each sequence of actions.

## Handler Pattern

The handler pattern is used to:

1. Constrain inputs to reasonable values using the `bound()` function
2. Track the state of created bonds using the `knownBonds` mapping
3. Keep counters (`totalCreatedBonds`, `totalReleasedBonds`, `totalPenalizedBonds`) to verify our invariants

## Running the Tests

To run just the invariant tests:

```bash
forge test --match-contract RiftReactorInvariantTest -vvv
```

The `-vvv` flag provides detailed information about each run, including the number of calls made, reverting calls, and the actual inputs used for each function call.

## Configuration

The invariant test runs for 256 sequences by default, with each sequence making multiple calls to the handler functions. This can be adjusted in `foundry.toml` if needed.
