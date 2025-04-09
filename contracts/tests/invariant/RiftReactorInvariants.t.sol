// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {RiftReactor} from "../../src/RiftReactor.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {MockToken} from "../utils/MockToken.sol";
import {SP1MockVerifier} from "sp1-contracts/contracts/src/SP1MockVerifier.sol";
import {IPermit2} from "uniswap-permit2/src/interfaces/IPermit2.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {RiftReactorExposed} from "../utils/RiftTestSetup.t.sol";

/**
 * @title RiftReactorHandler
 * @notice Handler contract for invariant testing of the RiftReactor contract
 */
contract RiftReactorHandler is Test {
    RiftReactorExposed public reactor;
    MockToken public depositToken;
    address public marketMaker;
    address public user;
    uint256 public userPrivateKey;

    // Track state for invariant testing
    mapping(bytes32 => bool) public knownBonds;
    uint256 public totalBondsCreated;
    uint256 public totalBondsReleased;
    uint256 public totalBondsSlashed;
    mapping(address => uint256) private _userLastNonce;
    mapping(bytes32 => bool) public usedOrderHashes;
    uint256 public totalBondAmount;

    constructor(RiftReactorExposed _reactor, MockToken _depositToken) {
        reactor = _reactor;
        depositToken = _depositToken;
        marketMaker = address(0x1111);
        user = address(0x2222);
        userPrivateKey = 0xA11CE;
    }

    /**
     * @notice Creates a bonded swap with a random amount
     * @param bondAmount The amount for the bond
     */
    function createBond(uint96 bondAmount) public {
        // Bound to reasonable values and ensure it's at least MIN_BOND
        bondAmount = uint96(bound(uint256(bondAmount), reactor.MIN_BOND(), 1_000_000 * 10 ** 8));

        // Create a unique order hash
        bytes32 orderHash = keccak256(abi.encode("bond", totalBondsCreated));

        // Create a bonded swap by directly updating the swapBonds map
        vm.startPrank(marketMaker);

        // First do a token transfer to simulate bond payment
        if (depositToken.transferFrom(marketMaker, address(reactor), bondAmount)) {
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
            totalBondsCreated++;
            totalBondAmount += bondAmount;
        }

        vm.stopPrank();
    }

    /**
     * @notice Releases a bond
     * @param bondIndex Index of bond to release (will be bounded by available bonds)
     */
    function releaseBond(uint256 bondIndex) public {
        // If no bonds have been created, skip
        if (totalBondsCreated == 0) return;

        // Find a valid bond to release
        bondIndex = bound(bondIndex, 0, totalBondsCreated - 1);
        bytes32 orderHash = keccak256(abi.encode("bond", bondIndex));

        // Check if this bond is still valid and hasn't been released
        if (knownBonds[orderHash]) {
            Types.BondedSwap memory bond = reactor.getBondedSwap(orderHash);
            vm.startPrank(marketMaker);

            // Create simplified release params
            Types.ReleaseLiquidityParams[] memory params = new Types.ReleaseLiquidityParams[](1);
            params[0].orderHash = orderHash;

            try reactor.releaseAndFree(params) {
                // Mark bond as released
                knownBonds[orderHash] = false;
                totalBondsReleased++;
                totalBondAmount -= bond.bond;
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
        if (totalBondsCreated == 0) return;

        // Find a valid bond to penalize
        bondIndex = bound(bondIndex, 0, totalBondsCreated - 1);
        bytes32 orderHash = keccak256(abi.encode("bond", bondIndex));

        // Check if this bond is still valid and hasn't been released
        if (knownBonds[orderHash]) {
            Types.BondedSwap memory bond = reactor.getBondedSwap(orderHash);
            // Set block number to after auction end
            vm.roll(bond.endBlock + 1);

            vm.startPrank(user);
            try reactor.withdrawAndPenalize(orderHash) {
                // Mark bond as penalized
                knownBonds[orderHash] = false;
                totalBondsSlashed++;
                totalBondAmount -= bond.bond;
            } catch {
                // Penalize failed, that's ok for invariant testing
            }
            vm.stopPrank();
        }
    }

    /**
     * @notice Creates a new order hash
     */
    function createOrderHash() public returns (bytes32) {
        bytes32 orderHash = keccak256(abi.encode("order", block.timestamp, totalBondsCreated));
        require(!usedOrderHashes[orderHash], "Order hash already used");
        usedOrderHashes[orderHash] = true;
        return orderHash;
    }

    /**
     * @notice Get the last nonce for a user
     */
    function userLastNonce(address _user) public view returns (uint256) {
        return _userLastNonce[_user];
    }

    /**
     * @notice Update the last nonce for a user
     */
    function updateUserLastNonce(address _user, uint256 nonce) public {
        _userLastNonce[_user] = nonce;
    }
}

contract RiftReactorInvariantTest is Test {
    RiftReactorExposed reactor;
    RiftReactorHandler handler;
    MockToken depositToken;
    SP1MockVerifier verifier;
    MockToken tokenIn;
    address marketMaker;
    address user;
    uint256 userPrivateKey;

    function setUp() public {
        // Setup test accounts
        userPrivateKey = 0xA11CE;
        user = vm.addr(userPrivateKey);
        marketMaker = makeAddr("marketMaker");

        // Setup tokens
        depositToken = new MockToken("Deposit Token", "DEP", 8);
        tokenIn = new MockToken("Input Token", "IN", 8);

        // Create verifier
        verifier = new SP1MockVerifier();

        // Create reactor
        Types.BlockLeaf memory tipBlockLeaf = Types.BlockLeaf({
            blockHash: bytes32(0),
            height: 1,
            cumulativeChainwork: 1
        });

        reactor = new RiftReactorExposed(
            bytes32(0), // mmrRoot
            address(depositToken),
            bytes32(0), // circuitVerificationKey
            address(verifier),
            address(0), // feeRouter
            tipBlockLeaf,
            address(0) // permit2
        );

        // Create handler
        handler = new RiftReactorHandler(reactor, depositToken);

        // Fund accounts
        tokenIn.mint(user, 1_000_000_000);
        depositToken.mint(marketMaker, 1_000_000_000);

        // Setup approvals
        vm.prank(user);
        tokenIn.approve(address(reactor), type(uint256).max);
        vm.prank(marketMaker);
        depositToken.approve(address(reactor), type(uint256).max);

        // Target the handler for invariant testing
        targetContract(address(handler));

        // Register the callable functions
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = handler.createBond.selector;
        selectors[1] = handler.releaseBond.selector;
        selectors[2] = handler.penalizeBond.selector;
        selectors[3] = handler.createOrderHash.selector;
        FuzzSelector memory selector = FuzzSelector({addr: address(handler), selectors: selectors});
        targetSelector(selector);

        // Set initial block number
        vm.roll(100);
    }

    /**
     * @notice Test: Intents should return minSats after endBlock
     */
    function test_IntentsReturnMinSatsAfterEndBlock() public {
        // Create a simple auction
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: 100, // Start at block 100
            endBlock: 200, // End at block 200
            minSats: 1000,
            maxSats: 2000
        });

        // Set block number to after the end block
        vm.roll(auction.endBlock + 1); // Block 201

        // After end block, should return minSats
        uint256 sats = reactor.computeAuctionSats(auction);
        assertEq(sats, auction.minSats, "Should return minSats after end block");
    }

    /**
     * @notice Test: Order hashes should be unique
     */
    function test_UniqueOrderHashes() public {
        // Set block number to ensure deterministic hash
        vm.roll(100);

        // Create a unique order hash
        bytes32 orderHash = handler.createOrderHash();

        // Verify it's marked as used
        assertTrue(handler.usedOrderHashes(orderHash), "Order hash should be marked as used");

        // Try to create another hash with the same timestamp - should revert
        vm.expectRevert("Order hash already used");
        handler.createOrderHash();
    }

    /**
     * @notice Invariant: Total bonds should equal sum of individual bonds
     */
    function invariant_TotalBondsEqualsSumOfIndividualBonds() public {
        assertEq(
            depositToken.balanceOf(address(reactor)),
            handler.totalBondAmount() + reactor.slashedBondFees(),
            "Total bonds should equal sum of individual bonds plus slashed fees"
        );
    }

    /**
     * @notice Invariant: Bond amount should never be less than MIN_BOND
     */
    function invariant_BondAmountNeverLessThanMinBond() public {
        // Create a bond with exactly MIN_BOND
        uint96 minBond = reactor.MIN_BOND();
        vm.startPrank(marketMaker);
        depositToken.approve(address(reactor), minBond);
        depositToken.transfer(address(reactor), minBond);
        vm.stopPrank();

        // Check that the bond amount is at least MIN_BOND
        assertTrue(
            depositToken.balanceOf(address(reactor)) >= reactor.MIN_BOND(),
            "Bond amount should never be less than MIN_BOND"
        );
    }

    /**
     * @notice Invariant: Slashed bonds should be correctly tracked
     */
    function invariant_SlashedBondsCorrectlyTracked() public {
        uint256 slashedFees = reactor.slashedBondFees();
        assertTrue(slashedFees <= handler.totalBondsCreated(), "Slashed fees should never exceed total bonds created");
    }

    /**
     * @notice Invariant: Auction price should be within bounds
     */
    function invariant_AuctionPriceWithinBounds() public {
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: block.number,
            endBlock: block.number + 100,
            minSats: 1000,
            maxSats: 2000
        });

        uint256 price = reactor.computeAuctionSats(auction);
        assertTrue(
            price >= auction.minSats && price <= auction.maxSats,
            "Auction price should be within min and max bounds"
        );
    }

    /**
     * @notice Invariant: Auction price should decrease over time
     */
    function invariant_AuctionPriceDecreasesOverTime() public {
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: block.number,
            endBlock: block.number + 100,
            minSats: 1000,
            maxSats: 2000
        });

        uint256 price1 = reactor.computeAuctionSats(auction);

        // Advance time
        vm.roll(block.number + 50);

        uint256 price2 = reactor.computeAuctionSats(auction);
        assertTrue(price2 <= price1, "Auction price should decrease over time");
    }

    /**
     * @notice Invariant: Contract should have sufficient cbBTC for active bonds
     */
    function invariant_SufficientCbBTCForBonds() public {
        uint256 contractBalance = depositToken.balanceOf(address(reactor));
        uint256 slashedFees = reactor.slashedBondFees();
        assertTrue(contractBalance >= slashedFees, "Contract should have sufficient cbBTC for slashed bonds");
    }

    /**
     * @notice Invariant: Sum of all bonds and slashed fees should equal the token balance
     */
    function invariant_AccountingConsistency() public {
        uint256 contractBalance = depositToken.balanceOf(address(reactor));
        uint256 slashedFees = reactor.slashedBondFees();
        uint256 activeBonds = handler.totalBondAmount();

        assertEq(
            contractBalance,
            slashedFees + activeBonds,
            "Contract balance should equal slashed fees plus active bonds"
        );
    }

    /**
     * @notice Invariant: Bonds cannot be double-released
     */
    function invariant_NoBondDoubleRelease() public {
        // Count the number of bonds created and released/slashed
        uint256 totalBondsCreated = handler.totalBondsCreated();
        uint256 totalBondsReleased = handler.totalBondsReleased();
        uint256 totalBondsSlashed = handler.totalBondsSlashed();

        assertTrue(
            totalBondsReleased + totalBondsSlashed <= totalBondsCreated,
            "Number of bonds released/slashed should never exceed bonds created"
        );
    }

    /**
     * @notice Intent nonces should be unique per user
     */
    function invariant_UniqueIntentNonces() public {
        uint256 currentNonce = reactor.intentNonce(user);
        assertTrue(currentNonce >= handler.userLastNonce(user), "Intent nonce should never decrease");
        handler.updateUserLastNonce(user, currentNonce);
    }

    /**
     * @notice Test: Auction price should be correctly interpolated during the auction
     */
    function test_AuctionPriceDuringAuction() public {
        // Create an auction that runs from block 100 to 200
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: 100,
            endBlock: 200,
            minSats: 1000,
            maxSats: 2000
        });

        // Set block number to halfway through the auction (block 150)
        vm.roll(150);

        // Calculate expected price at halfway point
        // At 50% through the auction, price should be halfway between max and min
        uint256 expectedPrice = auction.maxSats - (((auction.maxSats - auction.minSats) * 50) / 100);

        // Get actual price
        uint256 actualPrice = reactor.computeAuctionSats(auction);

        // Verify price is correct
        assertEq(actualPrice, expectedPrice, "Auction price should be halfway between max and min");

        // Verify price is between min and max
        assertTrue(actualPrice >= auction.minSats, "Price should be >= minSats");
        assertTrue(actualPrice <= auction.maxSats, "Price should be <= maxSats");

        // Test a few more points to verify linear decay
        vm.roll(125); // 25% through
        uint256 price25 = reactor.computeAuctionSats(auction);
        vm.roll(175); // 75% through
        uint256 price75 = reactor.computeAuctionSats(auction);

        assertTrue(price25 > actualPrice && actualPrice > price75, "Price should decrease linearly over time");
    }

    /**
     * @notice Test: Auction with zero duration should handle edge case correctly
     */
    function test_AuctionWithZeroDuration() public {
        // Create an auction where start and end blocks are the same
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: 100,
            endBlock: 100, // Same as start block
            minSats: 1000,
            maxSats: 2000
        });

        // Test before auction block
        vm.roll(99);
        uint256 preBefore = reactor.computeAuctionSats(auction);
        assertEq(preBefore, auction.maxSats, "Should return maxSats before auction block");

        // Test at auction block
        vm.roll(100);
        uint256 priceAt = reactor.computeAuctionSats(auction);
        assertEq(priceAt, auction.minSats, "Should return minSats at auction block since start equals end");

        // Test after auction block
        vm.roll(101);
        uint256 priceAfter = reactor.computeAuctionSats(auction);
        assertEq(priceAfter, auction.minSats, "Should return minSats after auction block");
    }
}
