// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {MockToken} from "../../utils/MockToken.sol";

// Enhanced exposed contract to include the functions we need to test
contract RiftReactorExposedForReleaseTests is RiftReactorExposed {
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

    // Get a bonded swap by order hash
    function getBondedSwap(bytes32 orderHash) public view override returns (Types.BondedSwap memory) {
        return swapBonds[orderHash];
    }

    // Override releaseAndFree to focus on just the bond functionality that we're testing
    function releaseAndFree(bytes32[] calldata orderHashes) public {
        uint256 i;
        uint256 orderHashesLength = orderHashes.length;
        for (; i < orderHashesLength; ) {
            bytes32 orderHash = orderHashes[i];
            // Retrieve the bonded swap record for this release request using
            // the order hash.
            Types.BondedSwap memory swapInfo = swapBonds[orderHash];
            // Ensure a valid bond is recorded.
            if (swapInfo.marketMaker == address(0)) revert Errors.BondNotFoundOrAlreadyReleased();

            // Release the full bond amount back to the market maker (no penalty applied here).
            bool success = DEPOSIT_TOKEN.transfer(swapInfo.marketMaker, swapInfo.bond);
            if (!success) revert Errors.BondReleaseTransferFailed();

            // Clear the bond record to prevent double releasing.
            delete swapBonds[orderHash];

            unchecked {
                ++i;
            }
        }
    }
}

contract ReleaseAndFreeTest is RiftTestSetup {
    // Constants
    uint256 constant DECIMALS = 8;
    uint256 constant TOKEN_MULTIPLIER = 10 ** DECIMALS;
    uint256 constant BOND_AMOUNT = 1 * TOKEN_MULTIPLIER; // 1 token

    // Test accounts
    address marketMaker;
    address user;

    // Enhanced reactor for testing
    RiftReactorExposedForReleaseTests public reactor;

    // Test data
    bytes32 orderHash;

    function setUp() public override {
        super.setUp();

        // Setup additional test accounts
        marketMaker = makeAddr("marketMaker");
        user = makeAddr("user");

        // Create new reactor with enhanced functionality
        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
        reactor = new RiftReactorExposedForReleaseTests({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _tipBlockLeaf: initial_mmr_proof.blockLeaf,
            _permit2_address: address(permit2)
        });

        // Fund accounts
        vm.startPrank(address(this));
        mockToken.mint(address(reactor), BOND_AMOUNT * 10); // Fund reactor with tokens
        vm.stopPrank();

        // Create a unique order hash for testing
        orderHash = keccak256(abi.encodePacked("test_order_hash"));
    }

    // Helper to create release params for testing
    function createReleaseParams(bytes32 hash) internal pure returns (bytes32[] memory) {
        bytes32[] memory orderHashes = new bytes32[](1);
        orderHashes[0] = hash;
        return orderHashes;
    }

    /// @notice Test successful release and free for a single bond
    function testReleaseAndFreeSuccess() public {
        // Create a bonded swap
        reactor.createBondedSwap(orderHash, marketMaker, uint96(BOND_AMOUNT), block.number);

        // Get initial balances
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);

        // Create release params
        bytes32[] memory orderHashes = createReleaseParams(orderHash);

        // Execute the release
        reactor.releaseAndFree(orderHashes);

        // Verify the results
        assertEq(
            mockToken.balanceOf(marketMaker),
            initialMakerBalance + BOND_AMOUNT,
            "Market maker should receive full bond amount"
        );

        // Verify the bond was deleted
        Types.BondedSwap memory bondAfter = reactor.getBondedSwap(orderHash);
        assertEq(bondAfter.marketMaker, address(0), "Bond should be deleted after release");
    }

    /// @notice Test releasing multiple bonds at once
    function testReleaseAndFreeMultiple() public {
        // Create three bonded swaps
        bytes32 hash1 = keccak256(abi.encodePacked("order_1"));
        bytes32 hash2 = keccak256(abi.encodePacked("order_2"));
        bytes32 hash3 = keccak256(abi.encodePacked("order_3"));

        reactor.createBondedSwap(hash1, marketMaker, uint96(BOND_AMOUNT), block.number);
        reactor.createBondedSwap(hash2, marketMaker, uint96(BOND_AMOUNT), block.number);
        reactor.createBondedSwap(hash3, marketMaker, uint96(BOND_AMOUNT), block.number);

        // Get initial balances
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);

        // Create release params for all three bonds
        bytes32[] memory orderHashes = new bytes32[](3);
        orderHashes[0] = hash1;
        orderHashes[1] = hash2;
        orderHashes[2] = hash3;

        // Execute the release
        reactor.releaseAndFree(orderHashes);

        // Verify the results
        assertEq(
            mockToken.balanceOf(marketMaker),
            initialMakerBalance + (BOND_AMOUNT * 3),
            "Market maker should receive full bond amount for all three orders"
        );

        // Verify all bonds were deleted
        assertEq(reactor.getBondedSwap(hash1).marketMaker, address(0), "Bond 1 should be deleted");
        assertEq(reactor.getBondedSwap(hash2).marketMaker, address(0), "Bond 2 should be deleted");
        assertEq(reactor.getBondedSwap(hash3).marketMaker, address(0), "Bond 3 should be deleted");
    }

    /// @notice Test releasing a non-existent bond
    function testReleaseAndFreeNonExistent() public {
        // Try to release a non-existent bond
        bytes32 nonExistentHash = keccak256(abi.encodePacked("non_existent_order"));
        bytes32[] memory orderHashes = createReleaseParams(nonExistentHash);

        vm.expectRevert(Errors.BondNotFoundOrAlreadyReleased.selector);
        reactor.releaseAndFree(orderHashes);
    }

    /// @notice Test releasing a bond twice
    function testReleaseAndFreeTwice() public {
        // Create a bonded swap
        reactor.createBondedSwap(orderHash, marketMaker, uint96(BOND_AMOUNT), block.number);

        // First release should succeed
        bytes32[] memory orderHashes = createReleaseParams(orderHash);
        reactor.releaseAndFree(orderHashes);

        // Second release should revert
        vm.expectRevert(Errors.BondNotFoundOrAlreadyReleased.selector);
        reactor.releaseAndFree(orderHashes);
    }

    /// @notice Test transfer failure handling
    function testReleaseAndFreeTransferFailure() public {
        // Create a bonded swap
        reactor.createBondedSwap(orderHash, marketMaker, uint96(BOND_AMOUNT), block.number);

        // Mock the transfer call to return false
        bytes memory transferCalldata = abi.encodeWithSelector(mockToken.transfer.selector, marketMaker, BOND_AMOUNT);

        vm.mockCall(address(mockToken), transferCalldata, abi.encode(false));

        // Create release params
        bytes32[] memory orderHashes = createReleaseParams(orderHash);

        // Expect the correct error when transfer fails
        vm.expectRevert(Errors.BondReleaseTransferFailed.selector);
        reactor.releaseAndFree(orderHashes);

        // Clean up the mock
        vm.clearMockedCalls();
    }

    /// @notice Test partial success - some bonds exist, others don't
    function testReleaseAndFreePartialSuccess() public {
        // Create two real bonds
        bytes32 hash1 = keccak256(abi.encodePacked("order_1"));
        bytes32 hash2 = keccak256(abi.encodePacked("order_2"));
        bytes32 nonExistentHash = keccak256(abi.encodePacked("non_existent_order"));

        reactor.createBondedSwap(hash1, marketMaker, uint96(BOND_AMOUNT), block.number);
        reactor.createBondedSwap(hash2, marketMaker, uint96(BOND_AMOUNT), block.number);

        // Get initial balances
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);

        // Create release params with a mix of existing and non-existing bonds
        bytes32[] memory orderHashes = new bytes32[](3);
        orderHashes[0] = hash1;
        orderHashes[1] = nonExistentHash; // This one should cause a revert
        orderHashes[2] = hash2;

        // Execute the release - the test should revert on the non-existent hash
        vm.expectRevert(Errors.BondNotFoundOrAlreadyReleased.selector);
        reactor.releaseAndFree(orderHashes);

        // Verify no bonds were processed (function reverted)
        assertEq(
            mockToken.balanceOf(marketMaker),
            initialMakerBalance,
            "No tokens should be transferred when function reverts"
        );

        // The bonds should still exist
        assertEq(reactor.getBondedSwap(hash1).marketMaker, marketMaker, "Bond 1 should still exist");

        assertEq(reactor.getBondedSwap(hash2).marketMaker, marketMaker, "Bond 2 should still exist");
    }
}
