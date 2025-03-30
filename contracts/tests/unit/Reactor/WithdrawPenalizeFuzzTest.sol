// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {MockToken} from "../../utils/MockToken.sol";

// Enhanced exposed contract for withdraw and penalize fuzz tests
contract RiftReactorExposedForWithdrawFuzz is RiftReactorExposed {
    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        Types.BlockLeaf memory _tipBlockLeaf,
        address _permit2_address
    )
        RiftReactorExposed(
            _mmrRoot,
            _depositToken,
            _circuitVerificationKey,
            _verifier,
            _feeRouter,
            _tipBlockLeaf,
            _permit2_address
        )
    {}

    // Function to create a bonded swap for testing
    function createBondedSwap(bytes32 orderHash, address marketMaker, uint96 bondAmount, uint256 endBlock) public {
        swapBonds[orderHash] = Types.BondedSwap({marketMaker: marketMaker, bond: bondAmount, endBlock: endBlock});
    }

    // Get current slashed bond fees
    function getSlashedBondFees() public view returns (uint256) {
        return slashedBondFees;
    }

    // Get a bonded swap by order hash
    function getBondedSwap(bytes32 orderHash) public view override returns (Types.BondedSwap memory) {
        return swapBonds[orderHash];
    }
}

contract WithdrawPenalizeFuzzTest is RiftTestSetup {
    // Constants
    uint16 constant SLASH_FEE_BIPS = 500; // 5% - should match contract value

    // Test accounts
    address marketMaker;
    address user;

    // Enhanced reactor for testing
    RiftReactorExposedForWithdrawFuzz public reactor;

    // Test data
    bytes32 orderHash;

    function setUp() public override {
        super.setUp();

        // Setup additional test accounts
        marketMaker = makeAddr("marketMaker");
        user = makeAddr("user");

        // Roll to a known block number to avoid underflows
        vm.roll(100);

        // Create new reactor with enhanced functionality
        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
        reactor = new RiftReactorExposedForWithdrawFuzz({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _tipBlockLeaf: initial_mmr_proof.blockLeaf,
            _permit2_address: address(permit2)
        });

        // Make sure we're using the correct mockToken
        mockToken = MockToken(address(reactor.DEPOSIT_TOKEN()));

        // Fund accounts
        vm.startPrank(address(this));
        // Mint plenty of tokens to the reactor for tests
        mockToken.mint(address(reactor), 1_000_000_000_000);
        // Also mint tokens to market maker for baseline
        mockToken.mint(marketMaker, 1_000_000_000);
        vm.stopPrank();

        // Create a unique order hash for testing
        orderHash = keccak256(abi.encodePacked("test_order_hash"));
    }

    /**
     * @notice Fuzz test to verify that withdrawAndPenalize correctly slashes bonds according to SLASH_FEE_BIPS
     * @param bondAmount The amount of the bond to test with
     */
    function testFuzz_WithdrawAndPenalizeSlashing(uint96 bondAmount) public {
        // Create a realistic bond amount - avoid tiny values and huge values
        vm.assume(bondAmount > 1000);
        vm.assume(bondAmount < 1_000_000_000_000);

        // Create a bonded swap with an auction that has ended
        uint256 pastEndBlock = block.number - 10;
        reactor.createBondedSwap(orderHash, marketMaker, bondAmount, pastEndBlock);

        // Verify the bond was created correctly
        Types.BondedSwap memory bond = reactor.getBondedSwap(orderHash);
        assertEq(bond.marketMaker, marketMaker, "Market maker should be set correctly");
        assertEq(bond.bond, bondAmount, "Bond amount should be set correctly");

        // Get initial balances for assertions
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);
        uint256 initialSlashedFees = reactor.getSlashedBondFees();

        // Calculate expected values
        uint256 expectedPenalty = (uint256(bondAmount) * SLASH_FEE_BIPS) / 10000;
        uint256 expectedRefund = bondAmount - expectedPenalty;

        // Execute the withdrawal
        reactor.withdrawAndPenalize(orderHash);

        // Verify the results
        assertEq(
            mockToken.balanceOf(marketMaker),
            initialMakerBalance + expectedRefund,
            "Market maker should receive refund amount"
        );

        assertEq(
            reactor.getSlashedBondFees(),
            initialSlashedFees + expectedPenalty,
            "Contract should record the penalty amount"
        );

        // Property: Total of refund + penalty should equal original bond
        assertEq(expectedRefund + expectedPenalty, bondAmount, "Refund + penalty should equal original bond");

        // Verify the bond was deleted
        Types.BondedSwap memory bondAfter = reactor.getBondedSwap(orderHash);
        assertEq(bondAfter.marketMaker, address(0), "Bond should be deleted after withdrawal");
    }

    /**
     * @notice Fuzz test to verify that multiple withdrawals with different bond amounts
     * accumulate correctly in the slashedBondFees
     * @param bondAmounts Array of bond amounts to test with
     */
    function testFuzz_WithdrawAndPenalizeMultiple(uint96[] calldata bondAmounts) public {
        // Limit the number of bonds for practical testing
        vm.assume(bondAmounts.length > 0 && bondAmounts.length <= 5);

        // Keep track of expected accumulated fees
        uint256 expectedTotalSlashedFees = 0;
        uint256 initialSlashedFees = reactor.getSlashedBondFees();

        // Process each bond amount
        for (uint i = 0; i < bondAmounts.length; i++) {
            // Skip very small or very large values
            if (bondAmounts[i] < 1000 || bondAmounts[i] > 1_000_000_000) continue;

            // Create a unique order hash for this bond
            bytes32 currentHash = keccak256(abi.encodePacked("test_order_", i));

            // Create the bonded swap
            uint256 pastEndBlock = block.number - 10;
            reactor.createBondedSwap(currentHash, marketMaker, bondAmounts[i], pastEndBlock);

            // Calculate expected penalty (safely)
            uint256 expectedPenalty = (uint256(bondAmounts[i]) * SLASH_FEE_BIPS) / 10000;

            // Ensure we don't overflow when adding to accumulated fees
            if (expectedTotalSlashedFees + expectedPenalty > type(uint256).max - expectedPenalty) {
                break; // Stop processing if we're at risk of overflowing
            }

            expectedTotalSlashedFees += expectedPenalty;

            // Withdraw and penalize
            reactor.withdrawAndPenalize(currentHash);
        }

        // Verify total accumulated fees
        assertEq(
            reactor.getSlashedBondFees(),
            initialSlashedFees + expectedTotalSlashedFees,
            "Total accumulated slashed fees should match expected value"
        );
    }

    /**
     * @notice Fuzz test to verify that the SLASH_FEE_BIPS is correctly applied for edge-case bond amounts
     * @param bondAmount The bond amount to test
     */
    function testFuzz_WithdrawAndPenalizeEdgeCases(uint96 bondAmount) public {
        // Skip zero bond amounts and limit to reasonable values
        vm.assume(bondAmount > 0 && bondAmount < 1_000_000_000);

        // Create a bonded swap
        uint256 pastEndBlock = block.number - 10;
        reactor.createBondedSwap(orderHash, marketMaker, bondAmount, pastEndBlock);

        // Get initial state
        uint256 initialSlashedFees = reactor.getSlashedBondFees();
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);

        // Calculate expected values with exact math
        uint256 expectedPenalty = (uint256(bondAmount) * SLASH_FEE_BIPS) / 10000;
        uint256 expectedRefund = bondAmount - expectedPenalty;

        // Execute the withdrawal
        reactor.withdrawAndPenalize(orderHash);

        // Property: Exact penalty amount should be added to slashedBondFees
        assertEq(
            reactor.getSlashedBondFees() - initialSlashedFees,
            expectedPenalty,
            "Exact penalty amount should be added to slashedBondFees"
        );

        // Property: Exact refund amount should be sent to market maker
        assertEq(
            mockToken.balanceOf(marketMaker) - initialMakerBalance,
            expectedRefund,
            "Market maker should receive exact refund amount"
        );

        // Property: No rounding errors should occur (sum should equal original)
        assertEq(expectedRefund + expectedPenalty, bondAmount, "No rounding errors should occur");
    }
}
