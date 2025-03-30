// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {Test, Vm} from "forge-std/src/Test.sol";
import {StdInvariant} from "forge-std/src/StdInvariant.sol";
import {RiftReactor} from "../../src/RiftReactor.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {MockToken} from "../utils/MockToken.sol";
import {RiftTestSetup, RiftReactorExposed} from "../utils/RiftTestSetup.t.sol";

/**
 * @title RiftReactorHandler
 * @notice Handler contract for invariant testing of the RiftReactor contract
 */
contract RiftReactorHandler is Test {
    RiftReactorExposed public reactor;
    MockToken public token;
    address public marketMaker;
    address public user;

    // Keep track of created bonds for invariant testing
    mapping(bytes32 => bool) public knownBonds;
    uint256 public totalCreatedBonds;
    uint256 public totalReleasedBonds;
    uint256 public totalPenalizedBonds;
    uint256 public accumulatedFees;

    // Constants
    uint96 public constant MIN_BOND = 0.0003 * 10 ** 8;
    uint16 public constant BOND_BIPS = 100;
    uint16 public constant SLASH_FEE_BIPS = 500;

    constructor(RiftReactorExposed _reactor, MockToken _token) {
        reactor = _reactor;
        token = _token;
        marketMaker = address(0x1111);
        user = address(0x2222);

        // Fund accounts
        token.mint(marketMaker, 1_000_000_000);
        token.mint(address(reactor), 1_000_000_000);

        // Approve token spending
        vm.startPrank(marketMaker);
        token.approve(address(reactor), type(uint256).max);
        vm.stopPrank();
    }

    /**
     * @notice Creates a bonded swap with a random amount
     * @param bondAmount The amount for the bond
     */
    function createBond(uint96 bondAmount) public {
        // Bound to reasonable values
        bondAmount = uint96(bound(uint256(bondAmount), MIN_BOND, 1_000_000 * 10 ** 8));

        // Create a unique order hash
        bytes32 orderHash = keccak256(abi.encode("bond", totalCreatedBonds));

        // Create a bonded swap by directly updating the swapBonds map
        vm.startPrank(marketMaker);

        // First do a token transfer to simulate bond payment
        if (token.transferFrom(marketMaker, address(reactor), bondAmount)) {
            // If transfer succeeds, create the bond
            Types.BondedSwap memory bond = Types.BondedSwap({
                marketMaker: marketMaker,
                bond: bondAmount,
                endBlock: block.number + 100 // Set end block 100 blocks in the future
            });

            // Record the bond in the reactor's storage
            reactor.setSwapBond(orderHash, bond);

            // Track the bond in our handler
            knownBonds[orderHash] = true;
            totalCreatedBonds++;
        }

        vm.stopPrank();
    }

    /**
     * @notice Releases a bond
     * @param bondIndex Index of bond to release (will be bounded by available bonds)
     */
    function releaseBond(uint256 bondIndex) public {
        // If no bonds have been created, skip
        if (totalCreatedBonds == 0) return;

        // Find a valid bond to release
        bondIndex = bound(bondIndex, 0, totalCreatedBonds - 1);
        bytes32 orderHash = keccak256(abi.encode("bond", bondIndex));

        // Check if this bond is still valid and hasn't been released
        if (knownBonds[orderHash]) {
            vm.startPrank(marketMaker);

            // Create simplified release params
            Types.ReleaseLiquidityParams[] memory params = new Types.ReleaseLiquidityParams[](1);
            params[0].orderHash = orderHash;

            try reactor.releaseAndFree(params) {
                // Mark bond as released
                knownBonds[orderHash] = false;
                totalReleasedBonds++;
            } catch {
                // Release failed, that's ok for invariant testing
            }
            vm.stopPrank();
        }
    }

    /**
     * @notice Penalizes a bond
     * @param bondIndex Index of bond to penalize (will be bounded by available bonds)
     */
    function penalizeBond(uint256 bondIndex) public {
        // If no bonds have been created, skip
        if (totalCreatedBonds == 0) return;

        // Find a valid bond to penalize
        bondIndex = bound(bondIndex, 0, totalCreatedBonds - 1);
        bytes32 orderHash = keccak256(abi.encode("bond", bondIndex));

        // Check if this bond is still valid and hasn't been released
        if (knownBonds[orderHash]) {
            // Set block number to after auction end
            Types.BondedSwap memory bonded = reactor.getBondedSwap(orderHash);
            vm.roll(bonded.endBlock + 1);

            vm.startPrank(user);
            try reactor.withdrawAndPenalize(orderHash) {
                // Mark bond as penalized
                knownBonds[orderHash] = false;
                totalPenalizedBonds++;

                // Track fees
                accumulatedFees += (uint256(bonded.bond) * SLASH_FEE_BIPS) / 10000;
            } catch {
                // Penalize failed, that's ok for invariant testing
            }
            vm.stopPrank();
        }
    }
}

/**
 * @title RiftReactorInvariantTest
 * @notice Invariant tests for RiftReactor
 */
contract RiftReactorInvariantTest is StdInvariant, RiftTestSetup {
    RiftReactorHandler public handler;

    function setUp() public override {
        super.setUp();

        // Create handler
        handler = new RiftReactorHandler(riftReactor, mockToken);

        // Target the handler for invariant testing
        targetContract(address(handler));

        // Register the callable functions
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = handler.createBond.selector;
        selectors[1] = handler.releaseBond.selector;
        selectors[2] = handler.penalizeBond.selector;
        FuzzSelector memory selector = FuzzSelector({addr: address(handler), selectors: selectors});
        targetSelector(selector);
    }

    /**
     * @notice Test that the total bonds is always equal to the sum of released and penalized bonds
     */
    function invariant_bondAccountingIsCorrect() public {
        assertLe(
            handler.totalReleasedBonds() + handler.totalPenalizedBonds(),
            handler.totalCreatedBonds(),
            "Total bonds released and penalized should not exceed total created"
        );
    }

    /**
     * @notice Test that the slashed fees are correctly tracked
     */
    function invariant_slashedFeesArePersisted() public {
        assertEq(
            handler.accumulatedFees(),
            riftReactor.slashedBondFees(),
            "Slashed fees should match the tracked accumulated fees"
        );
    }

    /**
     * @notice Test that the minimum bond amount is always respected
     */
    function invariant_minimumBondAmountRespected() public {
        uint96 minBond = riftReactor.MIN_BOND();

        // For all bonds that exist, check they're at least MIN_BOND
        for (uint256 i = 0; i < handler.totalCreatedBonds(); i++) {
            bytes32 orderHash = keccak256(abi.encode("bond", i));
            if (handler.knownBonds(orderHash)) {
                Types.BondedSwap memory bond = riftReactor.getBondedSwap(orderHash);
                assertGe(bond.bond, minBond, "Bond amount must be at least MIN_BOND");
            }
        }
    }
}
