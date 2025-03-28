// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {MockToken} from "../../utils/MockToken.sol";

// Enhanced exposed contract to include the functions we need to test
contract RiftReactorExposedForWithdrawTests is RiftReactorExposed {
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

    // Function to get current slashed bond fees
    function getSlashedBondFees() public view returns (uint256) {
        return slashedBondFees;
    }

    // Get a bonded swap by order hash
    function getBondedSwap(bytes32 orderHash) public view returns (Types.BondedSwap memory) {
        return swapBonds[orderHash];
    }
}

contract WithdrawAndPenalizeTest is RiftTestSetup {
    // Constants
    uint256 constant DECIMALS = 8;
    uint256 constant TOKEN_MULTIPLIER = 10 ** DECIMALS;
    uint256 constant BOND_AMOUNT = 1 * TOKEN_MULTIPLIER; // 1 token
    uint16 constant SLASH_FEE_BIPS = 500; // 5% - should match contract value

    // Test accounts
    address marketMaker;
    address user;

    // Enhanced reactor for testing
    RiftReactorExposedForWithdrawTests public reactor;

    // Test data
    bytes32 orderHash;

    function setUp() public override {
        super.setUp();

        // Setup additional test accounts
        marketMaker = makeAddr("marketMaker");
        user = makeAddr("user");

        // Roll to a known block number to avoid underflows
        vm.roll(100);
        console.log("Starting at block number:", block.number);

        // Create new reactor with enhanced functionality
        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
        reactor = new RiftReactorExposedForWithdrawTests({
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
        mockToken.mint(address(reactor), BOND_AMOUNT * 100);
        // Also mint tokens to market maker for baseline
        mockToken.mint(marketMaker, BOND_AMOUNT * 10);
        vm.stopPrank();

        console.log("Setup complete");
        console.log("Reactor token balance:", mockToken.balanceOf(address(reactor)));
        console.log("Market maker token balance:", mockToken.balanceOf(marketMaker));

        // Create a unique order hash for testing
        orderHash = keccak256(abi.encodePacked("test_order_hash"));
    }

    /// @notice Creates a bonded swap with finished auction
    function createFinishedAuctionBond() internal {
        // In test environment, block.number might be too low for subtraction
        // Make sure pastEndBlock is less than current block but doesn't underflow
        uint256 pastEndBlock;
        if (block.number > 10) {
            pastEndBlock = block.number - 10;
        } else {
            // Just use 0 if block.number is too low
            pastEndBlock = 0;
        }

        console.log("Current block number:", block.number);
        console.log("Using past end block:", pastEndBlock);

        reactor.createBondedSwap(orderHash, marketMaker, uint96(BOND_AMOUNT), pastEndBlock);
    }

    /// @notice Creates a bonded swap with ongoing auction
    function createOngoingAuctionBond() internal {
        // Create a bonded swap where the auction is still ongoing (endBlock > current block)
        uint256 futureEndBlock = block.number + 10;

        console.log("Current block number:", block.number);
        console.log("Using future end block:", futureEndBlock);

        reactor.createBondedSwap(orderHash, marketMaker, uint96(BOND_AMOUNT), futureEndBlock);
    }

    /// @notice Test successful withdraw and penalize when auction has ended
    function testWithdrawAndPenalizeSuccess() public {
        // Debug: Log initial state
        console.log("Initial reactor balance: ", mockToken.balanceOf(address(reactor)));
        console.log("Initial market maker balance: ", mockToken.balanceOf(marketMaker));

        // Create a bonded swap with an auction that has ended
        createFinishedAuctionBond();

        // Verify the bond was created correctly
        Types.BondedSwap memory bond = reactor.getBondedSwap(orderHash);
        console.log("Bond created. Market maker:", bond.marketMaker);
        console.log("Bond amount:", bond.bond);
        console.log("Bond end block:", bond.endBlock);
        assertTrue(bond.marketMaker == marketMaker, "Market maker should be set correctly");
        assertTrue(bond.bond == BOND_AMOUNT, "Bond amount should be set correctly");

        // Get initial balances for assertions
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);
        uint256 initialSlashedFees = reactor.getSlashedBondFees();

        // Calculate expected values
        uint256 expectedPenalty = (BOND_AMOUNT * SLASH_FEE_BIPS) / 10000;
        uint256 expectedRefund = BOND_AMOUNT - expectedPenalty;

        console.log("Expected penalty:", expectedPenalty);
        console.log("Expected refund:", expectedRefund);

        // Execute the withdrawal
        reactor.withdrawAndPenalize(orderHash);

        // Log final state
        console.log("Final market maker balance:", mockToken.balanceOf(marketMaker));
        console.log("Final slashed fees:", reactor.getSlashedBondFees());

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

        // Verify the bond was deleted
        Types.BondedSwap memory bondAfter = reactor.getBondedSwap(orderHash);
        assertEq(bondAfter.marketMaker, address(0), "Bond should be deleted after withdrawal");
    }

    /// @notice Test attempting to withdraw before auction ends
    function testWithdrawBeforeAuctionEnds() public {
        // Create a bonded swap with an ongoing auction
        createOngoingAuctionBond();

        // Try to withdraw - should revert
        vm.expectRevert(Errors.AuctionNotEnded.selector);
        reactor.withdrawAndPenalize(orderHash);
    }

    /// @notice Test attempting to withdraw from a non-existent bond
    function testWithdrawNonExistentBond() public {
        // Try to withdraw from a non-existent bond - should revert
        bytes32 nonExistentHash = keccak256(abi.encodePacked("non_existent_order"));

        vm.expectRevert(Errors.BondNotFoundOrAlreadyReleased.selector);
        reactor.withdrawAndPenalize(nonExistentHash);
    }

    /// @notice Test attempting to withdraw twice from the same bond
    function testWithdrawTwice() public {
        // Add debug output
        console.log("Initial reactor balance:", mockToken.balanceOf(address(reactor)));
        console.log("Initial market maker balance:", mockToken.balanceOf(marketMaker));

        // Create a bonded swap with an auction that has ended
        createFinishedAuctionBond();

        // Verify bond was created correctly
        Types.BondedSwap memory bond = reactor.getBondedSwap(orderHash);
        console.log("Bond created. Market maker:", bond.marketMaker);
        console.log("Bond amount:", bond.bond);
        assertTrue(bond.marketMaker == marketMaker, "Market maker should be set correctly");

        // Calculate expected values for logging
        uint256 expectedPenalty = (BOND_AMOUNT * SLASH_FEE_BIPS) / 10000;
        uint256 expectedRefund = BOND_AMOUNT - expectedPenalty;
        console.log("Expected penalty:", expectedPenalty);
        console.log("Expected refund:", expectedRefund);

        // First withdrawal should succeed
        console.log("Executing first withdrawal");
        reactor.withdrawAndPenalize(orderHash);

        // Verify bond was deleted
        bond = reactor.getBondedSwap(orderHash);
        assertEq(bond.marketMaker, address(0), "Bond should be deleted after first withdraw");

        console.log("Market maker balance after first withdrawal:", mockToken.balanceOf(marketMaker));

        // Second withdrawal should revert as the bond was deleted
        console.log("Attempting second withdrawal (should revert)");
        vm.expectRevert(Errors.BondNotFoundOrAlreadyReleased.selector);
        reactor.withdrawAndPenalize(orderHash);
    }

    /// @notice Test the penalty calculation - verify exact amounts
    function testWithdrawPenaltyCalculation() public {
        // Debug: Log initial state
        console.log("Initial market maker balance:", mockToken.balanceOf(marketMaker));

        // Create a bond with a specific amount to test penalty calculation
        uint96 bondAmount = 10000; // Use a nice round number to make calculation verification easy
        uint256 pastEndBlock = block.number - 10;

        reactor.createBondedSwap(orderHash, marketMaker, bondAmount, pastEndBlock);

        // Verify bond was created
        Types.BondedSwap memory bond = reactor.getBondedSwap(orderHash);
        console.log("Bond created. Market maker:", bond.marketMaker);
        console.log("Bond amount:", bond.bond);
        assertTrue(bond.marketMaker == marketMaker, "Market maker should be set correctly");
        assertTrue(bond.bond == bondAmount, "Bond amount should be set correctly");

        // Calculate expected penalty: (10000 * 500) / 10000 = 500
        uint256 expectedPenalty = (bondAmount * SLASH_FEE_BIPS) / 10000;
        uint256 expectedRefund = bondAmount - expectedPenalty;
        console.log("Expected penalty:", expectedPenalty);
        console.log("Expected refund:", expectedRefund);

        // Capture initial state
        uint256 initialSlashedFees = reactor.getSlashedBondFees();
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);

        // Execute the withdrawal
        reactor.withdrawAndPenalize(orderHash);

        // Log final state
        console.log("Final market maker balance:", mockToken.balanceOf(marketMaker));
        console.log("Final slashed fees:", reactor.getSlashedBondFees());

        // Verify the exact penalty amount
        assertEq(
            reactor.getSlashedBondFees() - initialSlashedFees,
            expectedPenalty,
            "Penalty calculation should match expected value"
        );

        // Verify the exact refund amount
        assertEq(
            mockToken.balanceOf(marketMaker),
            initialMakerBalance + expectedRefund,
            "Refund calculation should match expected value"
        );
    }

    /// @notice Test transfer failure handling
    function testWithdrawTransferFailure() public {
        // Add debug output
        console.log("Initial reactor balance:", mockToken.balanceOf(address(reactor)));
        console.log("Initial market maker balance:", mockToken.balanceOf(marketMaker));

        // Create a bonded swap with an auction that has ended
        createFinishedAuctionBond();

        // Verify bond was created correctly
        Types.BondedSwap memory bond = reactor.getBondedSwap(orderHash);
        console.log("Bond created. Market maker:", bond.marketMaker);
        console.log("Bond amount:", bond.bond);
        assertTrue(bond.marketMaker == marketMaker, "Market maker should be set correctly");

        // Calculate the amounts for mocking
        uint256 penalty = (BOND_AMOUNT * SLASH_FEE_BIPS) / 10000;
        uint256 refund = BOND_AMOUNT - penalty;
        console.log("Calculated penalty:", penalty);
        console.log("Calculated refund:", refund);

        // Mock the transfer call to return false
        console.log("Setting up mock to return false for transfer");
        bytes memory transferCalldata = abi.encodeWithSelector(mockToken.transfer.selector, marketMaker, refund);

        vm.mockCall(address(mockToken), transferCalldata, abi.encode(false));

        // Expect the correct error when transfer fails
        console.log("Calling withdrawAndPenalize (should revert with BondReleaseTransferFailed)");
        vm.expectRevert(Errors.BondReleaseTransferFailed.selector);
        reactor.withdrawAndPenalize(orderHash);

        // Clean up the mock
        vm.clearMockedCalls();
        console.log("Test complete, mock cleared");
    }
}
