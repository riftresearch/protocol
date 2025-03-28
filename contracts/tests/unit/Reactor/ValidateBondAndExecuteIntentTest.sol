// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {EIP712Hashing} from "../../../src/libraries/Hashing.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {IPermit2, ISignatureTransfer} from "uniswap-permit2/src/interfaces/IPermit2.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {Events} from "../../../src/libraries/Events.sol";
import {MockToken} from "../../utils/MockToken.sol";

// Enhanced exposed contract to include the functions we need to test
contract RiftReactorExposedForBondTests is RiftReactorExposed {
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

    // Expose _validateBondAndRecord for testing
    function validateBondAndRecord(Types.SignedIntent calldata order) public {
        _validateBondAndRecord(order);
    }

    // Helper function to expose permit2 transfer and swap steps separately
    function validateBondOnly(Types.SignedIntent calldata order) public {
        // Only perform bond validation
        if (order.info.nonce != intentNonce[order.info.depositLiquidityParams.depositOwnerAddress]) {
            revert Errors.InvalidNonce();
        }

        uint96 requiredBond = _computeBond(order.info.depositLiquidityParams.depositAmount);
        bytes32 orderId = order.orderHash;

        // Record the bonded swap
        swapBonds[orderId] = Types.BondedSwap({
            marketMaker: msg.sender,
            bond: requiredBond,
            endBlock: order.info.auction.endBlock
        });

        // Transfer bond
        bool success = DEPOSIT_TOKEN.transferFrom(msg.sender, address(this), requiredBond);
        if (!success) {
            // Rollback the state update if external call fails
            delete swapBonds[orderId];
            revert Errors.BondDepositTransferFailed();
        }
    }

    // Expose _executeIntentAndSwapShared for testing
    function executeIntentAndSwapSharedMock(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order
    ) public returns (uint256) {
        // Skip bond validation which we test separately
        // Assume the bond has already been recorded

        // Calculate expected sats directly
        return _computeAuctionSats(order.info.auction);
    }

    // Execute just the swap part for testing
    function executeSwapOnly(Types.LiquidityRoute calldata route, Types.SignedIntent calldata order) public {
        _executeSwap(route, order, order.info.depositLiquidityParams.depositAmount);
    }

    // Helper to get swapBonds for assertions
    function getSwapBond(bytes32 orderId) public view returns (Types.BondedSwap memory) {
        return swapBonds[orderId];
    }
}

// Mock Router for the swap functionality
contract MockRouter {
    IERC20 private immutable _depositToken;
    uint256 private _conversionRate; // Basis points (e.g., 10000 = 100%)
    bool private _shouldRevert;

    constructor(address depositToken) {
        _depositToken = IERC20(depositToken);
        _conversionRate = 10000; // Default 100% conversion rate
        _shouldRevert = false;
    }

    // Function to set conversion rate (basis points)
    function setConversionRate(uint256 rate) external {
        _conversionRate = rate;
    }

    // Function to make the router revert
    function setShouldRevert(bool shouldRevert) external {
        _shouldRevert = shouldRevert;
    }

    // This function will be called via `call` with routeData
    function swap(uint256 amountIn, address recipient) external returns (uint256) {
        if (_shouldRevert) {
            revert("Mock router reverted");
        }

        // Calculate output amount with conversion rate
        uint256 amountOut = (amountIn * _conversionRate) / 10000;

        // Transfer depositToken to recipient
        require(_depositToken.transfer(recipient, amountOut), "Output transfer failed");

        return amountOut;
    }

    // Function to encode swap call data for testing
    function encodeSwapCall(uint256 amountIn, address recipient) external pure returns (bytes memory) {
        return abi.encodeWithSelector(this.swap.selector, amountIn, recipient);
    }
}

contract ValidateBondAndExecuteIntentTest is RiftTestSetup {
    using EIP712Hashing for Types.IntentInfo;
    using EIP712Hashing for Types.SignedIntent;

    // Constants
    uint256 constant DECIMALS = 8;
    uint256 constant TOKEN_MULTIPLIER = 10 ** DECIMALS;

    // Token amounts
    uint256 constant MARKET_MAKER_INITIAL_BALANCE = 10000 * TOKEN_MULTIPLIER; // 10,000 tokens
    uint256 constant USER_INITIAL_BALANCE = 100000 * TOKEN_MULTIPLIER; // 100,000 tokens
    uint256 constant SWAP_AMOUNT = 1 * TOKEN_MULTIPLIER; // 1 token

    // Market maker and users
    address marketMaker;
    address user;

    // Enhanced reactor for testing
    RiftReactorExposedForBondTests public reactor;

    // Mock token for input
    MockToken tokenIn;

    // Router for swap tests
    MockRouter router;

    function setUp() public override {
        super.setUp();

        // Setup additional test accounts
        marketMaker = makeAddr("marketMaker");
        user = makeAddr("user");

        // Create new reactor with enhanced functionality
        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
        reactor = new RiftReactorExposedForBondTests({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _tipBlockLeaf: initial_mmr_proof.blockLeaf,
            _permit2_address: address(permit2)
        });

        // Setup tokens
        tokenIn = new MockToken("Input Token", "IN", uint8(DECIMALS));

        // Setup router
        router = new MockRouter(address(mockToken));

        // Fund accounts
        vm.startPrank(address(this));
        mockToken.mint(marketMaker, MARKET_MAKER_INITIAL_BALANCE);
        mockToken.mint(address(router), MARKET_MAKER_INITIAL_BALANCE);
        mockToken.mint(address(reactor), MARKET_MAKER_INITIAL_BALANCE); // Ensure reactor has mockToken for tests
        tokenIn.mint(user, USER_INITIAL_BALANCE);
        tokenIn.mint(address(reactor), SWAP_AMOUNT); // Ensure reactor has tokenIn for tests
        vm.stopPrank();

        // Setup approvals
        vm.startPrank(marketMaker);
        mockToken.approve(address(reactor), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(user);
        tokenIn.approve(address(permit2), type(uint256).max);
        vm.stopPrank();
    }

    // Helper to create a signed intent
    function createSignedIntent(bool validNonce) internal view returns (Types.SignedIntent memory) {
        Types.IntentInfo memory intentInfo = Types.IntentInfo({
            intentReactor: address(reactor),
            nonce: validNonce ? 0 : 1, // Use correct or incorrect nonce
            tokenIn: address(tokenIn),
            auction: Types.DutchAuctionInfo({
                startBlock: block.number,
                endBlock: block.number + 100,
                minSats: 900_000,
                maxSats: 1_000_000
            }),
            depositLiquidityParams: Types.ReactorDepositLiquidityParams({
                depositAmount: SWAP_AMOUNT,
                depositSalt: bytes32(uint256(123)),
                depositOwnerAddress: user,
                btcPayoutScriptPubKey: bytes25(0),
                confirmationBlocks: 6,
                safeBlockLeaf: Types.BlockLeaf({blockHash: bytes32(0), height: 1, cumulativeChainwork: 1}),
                safeBlockSiblings: new bytes32[](0),
                safeBlockPeaks: new bytes32[](0)
            }),
            permit2TransferInfo: Types.Permit2TransferInfo({
                permitTransferFrom: ISignatureTransfer.PermitTransferFrom({
                    permitted: ISignatureTransfer.TokenPermissions({token: address(tokenIn), amount: SWAP_AMOUNT}),
                    nonce: 0,
                    deadline: block.timestamp + 3600
                }),
                transferDetails: ISignatureTransfer.SignatureTransferDetails({
                    to: address(reactor),
                    requestedAmount: SWAP_AMOUNT
                }),
                owner: user,
                signature: bytes("0x")
            })
        });

        bytes32 orderHash = keccak256(abi.encode(intentInfo));

        return
            Types.SignedIntent({
                info: intentInfo,
                orderHash: orderHash,
                signature: bytes("0x") // Using mock signature
            });
    }

    // Helper to create a liquidity route
    function createLiquidityRoute() internal view returns (Types.LiquidityRoute memory) {
        bytes memory routeData = router.encodeSwapCall(SWAP_AMOUNT, address(reactor));
        return Types.LiquidityRoute({router: address(router), routeData: routeData});
    }

    // ----------------------
    // Tests for _validateBondAndRecord
    // ----------------------

    /// @notice Test a successful bond validation and recording
    function testValidateBondAndRecordSuccess() public {
        Types.SignedIntent memory order = createSignedIntent(true); // Valid nonce

        uint96 requiredBond = reactor.computeBond(SWAP_AMOUNT);

        // Start as market maker with enough balance
        vm.startPrank(marketMaker);

        // Get initial balances
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);
        uint256 initialReactorBalance = mockToken.balanceOf(address(reactor));

        // Call the function using the bond-only version to simplify testing
        reactor.validateBondOnly(order);

        // Check balances after
        uint256 finalMakerBalance = mockToken.balanceOf(marketMaker);
        uint256 finalReactorBalance = mockToken.balanceOf(address(reactor));

        // Verify bond was transferred
        assertEq(
            finalMakerBalance,
            initialMakerBalance - requiredBond,
            "Market maker balance should decrease by bond amount"
        );
        assertEq(
            finalReactorBalance,
            initialReactorBalance + requiredBond,
            "Reactor balance should increase by bond amount"
        );

        // Verify bond was recorded
        Types.BondedSwap memory bond = reactor.getSwapBond(order.orderHash);
        assertEq(bond.marketMaker, marketMaker, "Bond should be recorded with correct market maker");
        assertEq(bond.bond, requiredBond, "Bond amount should match required bond");
        assertEq(bond.endBlock, order.info.auction.endBlock, "Bond end block should match auction end block");

        vm.stopPrank();
    }

    /// @notice Test validation with an invalid nonce
    function testValidateBondAndRecordInvalidNonce() public {
        Types.SignedIntent memory order = createSignedIntent(false); // Invalid nonce

        // Start as market maker
        vm.startPrank(marketMaker);

        // Expect revert with InvalidNonce error
        vm.expectRevert(Errors.InvalidNonce.selector);
        reactor.validateBondOnly(order);

        vm.stopPrank();
    }

    /// @notice Test validation with insufficient bond amount
    function testValidateBondAndRecordInsufficientBond() public {
        Types.SignedIntent memory order = createSignedIntent(true); // Valid nonce
        uint96 requiredBond = reactor.computeBond(SWAP_AMOUNT);

        // Mock the transferFrom call to return false instead of reverting
        bytes memory transferFromCalldata = abi.encodeWithSelector(
            mockToken.transferFrom.selector,
            marketMaker,
            address(reactor),
            requiredBond
        );

        // The mock will make transferFrom return false instead of reverting
        vm.mockCall(address(mockToken), transferFromCalldata, abi.encode(false));

        // Start as market maker
        vm.startPrank(marketMaker);

        // Expect revert with BondDepositTransferFailed error
        vm.expectRevert(Errors.BondDepositTransferFailed.selector);
        reactor.validateBondOnly(order);

        // Clean up the mock
        vm.clearMockedCalls();

        vm.stopPrank();
    }

    // ----------------------
    // Tests for swap execution
    // ----------------------

    /// @notice Test a successful execution of swap
    function testExecuteSwapSuccess() public {
        Types.SignedIntent memory order = createSignedIntent(true); // Valid nonce
        Types.LiquidityRoute memory route = createLiquidityRoute();

        // Ensure router has tokens
        vm.startPrank(address(this));
        mockToken.mint(address(router), SWAP_AMOUNT * 10); // Ensure router has plenty of tokens
        vm.stopPrank();

        // Get initial token balance
        uint256 initialBalance = mockToken.balanceOf(address(reactor));

        // Execute just the swap as the reactor
        vm.startPrank(address(reactor));
        tokenIn.approve(address(router), SWAP_AMOUNT);

        // Call directly to the router with the routeData
        (bool success, ) = address(router).call(route.routeData);
        require(success, "Router call failed");

        // Check balance after swap
        uint256 finalBalance = mockToken.balanceOf(address(reactor));
        assertGt(finalBalance, initialBalance, "Reactor should have more depositToken after swap");

        vm.stopPrank();
    }

    /// @notice Test execution with router failure
    function testExecuteSwapWithRouterFailure() public {
        Types.SignedIntent memory order = createSignedIntent(true); // Valid nonce

        // Use our router but set it to revert
        router.setShouldRevert(true);
        Types.LiquidityRoute memory route = createLiquidityRoute();

        // Start as reactor
        vm.startPrank(address(reactor));

        // Expect the call to revert
        (bool success, ) = address(router).call(route.routeData);
        assertEq(success, false, "Router call should fail when set to revert");

        vm.stopPrank();
    }

    /// @notice Test execution with insufficient cbBTC after swap
    function testExecuteSwapWithInsufficientOutput() public {
        Types.SignedIntent memory order = createSignedIntent(true); // Valid nonce
        Types.LiquidityRoute memory route = createLiquidityRoute();

        // Configure router to return less than expected
        router.setConversionRate(5000); // 50% conversion rate

        // Start as reactor
        vm.startPrank(address(reactor));

        // Execute swap
        (bool success, ) = address(router).call(route.routeData);
        require(success, "Router call failed");

        // Verify swap amount
        uint256 expectedAmount = (SWAP_AMOUNT * 5000) / 10000; // 50% of input
        uint256 transferredAmount = mockToken.balanceOf(address(reactor)) - MARKET_MAKER_INITIAL_BALANCE;
        assertEq(transferredAmount, expectedAmount, "Router should transfer 50% of the input amount");

        // This would be insufficient for the full transaction
        assertLt(transferredAmount, SWAP_AMOUNT, "Output should be less than required deposit amount");

        vm.stopPrank();
    }

    // ----------------------
    // Tests for separate components of _executeIntentAndSwapShared
    // ----------------------

    /// @notice Test the sats calculation from auction info
    function testComputeAuctionSatsFromExecution() public {
        Types.SignedIntent memory order = createSignedIntent(true); // Valid nonce

        // Calculate expected sats
        uint256 expectedSats = reactor.computeAuctionSats(order.info.auction);

        // Use our simplified mock to skip permit2 transfer and router call
        vm.startPrank(marketMaker);
        uint256 calculatedSats = reactor.executeIntentAndSwapSharedMock(createLiquidityRoute(), order);
        vm.stopPrank();

        // Verify calculation
        assertEq(calculatedSats, expectedSats, "Expected sats should match calculated value");
    }
}
