// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {MockToken} from "../../utils/MockToken.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {IPermit2, ISignatureTransfer} from "uniswap-permit2/src/interfaces/IPermit2.sol";
import {EIP712Hashing} from "../../../src/libraries/Hashing.sol";
import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol";

// Mock Router contract for testing swaps with different conversion rates
contract ConfigurableRouter {
    address public immutable outputToken;
    uint256 public conversionRate;
    bool public shouldRevert;

    constructor(address _outputToken) {
        outputToken = _outputToken;
        conversionRate = 10000; // Default 100% conversion rate (1:1)
    }

    function setConversionRate(uint256 _rate) external {
        conversionRate = _rate;
    }

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function swap(uint256 amountIn, address recipient) external returns (uint256) {
        if (shouldRevert) {
            revert("Router call failed");
        }

        // Calculate output amount with conversion rate
        uint256 amountOut = (amountIn * conversionRate) / 10000;

        // Transfer output tokens to recipient
        bool success = IERC20(outputToken).transfer(recipient, amountOut);
        require(success, "Output transfer failed");

        return amountOut;
    }

    function encodeSwapCall(uint256 amountIn, address recipient) external pure returns (bytes memory) {
        return abi.encodeWithSelector(this.swap.selector, amountIn, recipient);
    }
}

// Enhanced exposed contract for testing executed intents
contract RiftReactorExposedForIntentFuzz is RiftReactorExposed {
    // Store the last swap amount for executeIntentAndSwapSharedTest
    uint256 public lastSwapOutput;

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

    // Expose _executeIntentAndSwapShared for testing
    function executeIntentAndSwapSharedTest(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order
    ) public returns (uint256) {
        console.log(
            "executeIntentAndSwapSharedTest: Starting test with amount",
            order.info.depositLiquidityParams.depositAmount
        );

        // Skip bond validation which is tested separately
        // Make _validateBondAndRecord a no-op for testing

        // Call permit2 to transfer tokens from user to reactor
        console.log("executeIntentAndSwapSharedTest: Calling permit2");
        PERMIT2.permitTransferFrom(
            order.info.permit2TransferInfo.permitTransferFrom,
            order.info.permit2TransferInfo.transferDetails,
            order.info.permit2TransferInfo.owner,
            order.info.permit2TransferInfo.signature
        );
        console.log("executeIntentAndSwapSharedTest: Permit2 transfer complete");

        // Reset last swap output
        lastSwapOutput = 0;

        // Store initial balance to calculate output
        uint256 balanceBefore = DEPOSIT_TOKEN.balanceOf(address(this));

        // Execute the swap
        console.log("executeIntentAndSwapSharedTest: Calling _executeSwap");
        _executeSwap(route, order, order.info.depositLiquidityParams.depositAmount);
        console.log("executeIntentAndSwapSharedTest: Swap complete");

        // Calculate output after swap
        uint256 balanceAfter = DEPOSIT_TOKEN.balanceOf(address(this));
        lastSwapOutput = balanceAfter - balanceBefore;
        console.log("executeIntentAndSwapSharedTest: Output amount:", lastSwapOutput);

        // Calculate expected sats
        console.log("executeIntentAndSwapSharedTest: Computing auction sats");
        uint256 expectedSats = _computeAuctionSats(order.info.auction);
        console.log("executeIntentAndSwapSharedTest: Expected sats:", expectedSats);

        return expectedSats;
    }

    // Override _executeSwap to add logging but preserve the same signature
    function _executeSwap(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order,
        uint256 amount
    ) internal override {
        console.log("_executeSwap: Starting with amount", amount);

        // Get the token to swap
        IERC20 tokenIn = IERC20(order.info.tokenIn);

        // Approve router to spend token
        console.log("_executeSwap: Approving router");
        bool success = tokenIn.approve(route.router, amount);
        require(success, "Router approval failed");

        // Keep track of the deposit token balance before the swap
        uint256 balanceBefore = DEPOSIT_TOKEN.balanceOf(address(this));
        console.log("_executeSwap: Balance before swap", balanceBefore);

        // Execute the route
        console.log("_executeSwap: Calling router");
        (bool routeSuccess, bytes memory returnData) = route.router.call(route.routeData);

        // Check if the route call was successful
        if (!routeSuccess) {
            console.log("_executeSwap: Router call failed");
            revert Errors.RouterCallFailed();
        }

        // Log the output but don't return it
        uint256 balanceAfter = DEPOSIT_TOKEN.balanceOf(address(this));
        uint256 outputAmount = balanceAfter - balanceBefore;
        console.log("_executeSwap: Output amount", outputAmount);

        // The parent validation will happen now
        super._executeSwap(route, order, amount);
    }

    // Allow the test to verify computed sats values
    function getComputedAuctionSats(Types.DutchAuctionInfo calldata auction) public view returns (uint256) {
        return _computeAuctionSats(auction);
    }

    // Allow test to create intent data hash - using manual hashing instead of EIP712Hashing library
    function hashIntentData(Types.IntentInfo calldata info) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "IntentInfo(address intentReactor,uint256 nonce,address tokenIn,DutchAuctionInfo auction,ReactorDepositLiquidityParams depositLiquidityParams,Permit2TransferInfo permit2TransferInfo)"
                ),
                info.intentReactor,
                info.nonce,
                info.tokenIn,
                keccak256(abi.encode(info.auction)),
                keccak256(abi.encode(info.depositLiquidityParams)),
                keccak256(abi.encode(info.permit2TransferInfo))
            )
        );

        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }
}

contract ExecuteIntentFuzzTest is RiftTestSetup {
    // Constants
    uint256 constant DECIMALS = 8;
    uint256 constant TOKEN_MULTIPLIER = 10 ** DECIMALS;
    uint256 constant MAX_TEST_AMOUNT = 1_000_000 * TOKEN_MULTIPLIER; // 1M tokens

    // Test accounts
    address marketMaker;
    address user;
    uint256 userPrivateKey; // Private key for user to sign permit2

    // Mock token for input
    MockToken tokenIn;

    // Router for swap tests
    ConfigurableRouter router;

    // Enhanced reactor for testing
    RiftReactorExposedForIntentFuzz public reactor;

    function setUp() public override {
        super.setUp();

        // Setup additional test accounts with deterministic private keys
        userPrivateKey = 0xA11CE;
        user = vm.addr(userPrivateKey);
        marketMaker = makeAddr("marketMaker");

        // Create new reactor with enhanced functionality
        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
        reactor = new RiftReactorExposedForIntentFuzz({
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
        router = new ConfigurableRouter(address(mockToken));

        // Fund accounts
        vm.startPrank(address(this));
        tokenIn.mint(user, MAX_TEST_AMOUNT * 2); // Double the max amount for safety
        mockToken.mint(address(router), MAX_TEST_AMOUNT * 2);
        vm.stopPrank();

        // Setup user approvals for permit2
        vm.startPrank(user);
        tokenIn.approve(address(permit2), type(uint256).max);
        vm.stopPrank();

        // Setup approvals for the router
        vm.startPrank(address(reactor));
        tokenIn.approve(address(router), type(uint256).max);
        vm.stopPrank();

        console.log("Setup complete");
        console.log("- permit2 address:", address(permit2));
        console.log("- user:", user);
        console.log("- tokenIn:", address(tokenIn));
        console.log("- router:", address(router));
    }

    /**
     * @notice Helper function to create a signed intent
     * @param amount Amount to swap
     * @param minSats Minimum sats for the auction
     * @param maxSats Maximum sats for the auction
     * @return signedIntent The created signed intent with a dummy signature
     */
    function createSignedIntent(
        uint256 amount,
        uint256 minSats,
        uint256 maxSats
    ) internal returns (Types.SignedIntent memory) {
        console.log("Creating intent with amount:", amount);

        // Create permit2 transfer - use simple values
        ISignatureTransfer.PermitTransferFrom memory permitTransferFrom = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(tokenIn), amount: amount}),
            nonce: 0,
            deadline: block.timestamp + 3600
        });

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({to: address(reactor), requestedAmount: amount});

        // Use a fixed dummy signature - our mock doesn't verify signatures
        bytes memory signature = abi.encodePacked(bytes32(uint256(0x1)), bytes32(uint256(0x2)), uint8(27));

        // Create permit2 transfer info
        Types.Permit2TransferInfo memory permit2TransferInfo = Types.Permit2TransferInfo({
            permitTransferFrom: permitTransferFrom,
            transferDetails: transferDetails,
            owner: user,
            signature: signature
        });

        // Create auction info
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: block.number,
            endBlock: block.number + 100,
            minSats: minSats,
            maxSats: maxSats
        });

        // Create deposit liquidity params - use simple values
        Types.ReactorDepositLiquidityParams memory depositParams = Types.ReactorDepositLiquidityParams({
            depositAmount: amount,
            depositSalt: bytes32(uint256(123)),
            depositOwnerAddress: user,
            btcPayoutScriptPubKey: bytes25(0),
            confirmationBlocks: 6,
            safeBlockLeaf: Types.BlockLeaf({blockHash: bytes32(0), height: 1, cumulativeChainwork: 1}),
            safeBlockSiblings: new bytes32[](0),
            safeBlockPeaks: new bytes32[](0)
        });

        // Create the intent info
        Types.IntentInfo memory intentInfo = Types.IntentInfo({
            intentReactor: address(reactor),
            nonce: 0,
            tokenIn: address(tokenIn),
            auction: auction,
            depositLiquidityParams: depositParams,
            permit2TransferInfo: permit2TransferInfo
        });

        // Just use a dummy orderHash
        bytes32 orderHash = keccak256(abi.encode(intentInfo));

        // Use the same dummy signature for the intent
        return Types.SignedIntent({info: intentInfo, signature: signature, orderHash: orderHash});
    }

    /**
     * @notice Helper function to create a signed intent with safe bounds on inputs
     * @param rawAmount Unbounded amount to swap (will be bounded internally)
     * @param rawMinSats Unbounded minimum sats for the auction (will be bounded internally)
     * @param rawMaxSats Unbounded maximum sats for the auction (will be bounded internally)
     * @return signedIntent The created signed intent with safe bounds
     */
    function createSafeSignedIntent(
        uint256 rawAmount,
        uint256 rawMinSats,
        uint256 rawMaxSats
    ) internal returns (Types.SignedIntent memory) {
        // Apply safe bounds to inputs
        uint256 amount = bound(rawAmount, 1000, 10_000);
        uint256 minSats = bound(rawMinSats, 1000, 5_000);
        uint256 maxSats = bound(rawMaxSats, minSats + 1000, minSats + 5_000);

        return createSignedIntent(amount, minSats, maxSats);
    }

    /**
     * @notice Test that executeIntentAndSwapShared correctly processes swaps
     */
    function test_ExecuteIntentAndSwapShared() public {
        console.log("Starting test_ExecuteIntentAndSwapShared");

        // Use small fixed values that won't cause overflow
        uint256 amount = 5000;
        uint256 conversionRate = 200; // 2%
        uint256 minSats = 2000;
        uint256 maxSats = 4000;

        // Calculate expected output
        uint256 expectedOutput = (amount * conversionRate) / 10000;
        console.log("Expected output:", expectedOutput);

        // Set router's conversion rate
        router.setConversionRate(conversionRate);
        console.log("Set router conversion rate to:", conversionRate);

        // Create signed intent with safe values
        console.log("Creating signed intent");
        Types.SignedIntent memory intent = createSignedIntent(amount, minSats, maxSats);
        console.log("Created intent with signature length:", intent.signature.length);

        // Create route with swap calldata
        console.log("Creating route");
        bytes memory routeData = router.encodeSwapCall(amount, address(reactor));
        Types.LiquidityRoute memory route = Types.LiquidityRoute({router: address(router), routeData: routeData});
        console.log("Created route with router:", address(router));

        // Make sure user has enough tokens for the test
        vm.startPrank(address(this));
        tokenIn.mint(user, amount);
        vm.stopPrank();
        console.log("Minted tokens to user. User balance:", tokenIn.balanceOf(user));

        // Check initial balances
        uint256 initialUserTokenIn = tokenIn.balanceOf(user);
        uint256 initialReactorDepositToken = mockToken.balanceOf(address(reactor));
        console.log("Initial balances - User:", initialUserTokenIn, "Reactor:", initialReactorDepositToken);

        // Execute the intent
        console.log("Executing intent as market maker:", marketMaker);
        vm.prank(marketMaker);
        uint256 expectedSats = reactor.executeIntentAndSwapSharedTest(route, intent);
        console.log("Intent executed. Expected sats:", expectedSats);

        // Get the swap output amount from the reactor
        uint256 outputAmount = reactor.lastSwapOutput();
        console.log("Last swap output:", outputAmount);

        // User should have less tokenIn
        uint256 finalUserTokenIn = tokenIn.balanceOf(user);
        console.log("Final user balance:", finalUserTokenIn);
        assertEq(
            finalUserTokenIn,
            initialUserTokenIn - amount,
            "User should have their tokenIn reduced by the swap amount"
        );

        // Reactor should have received deposit tokens
        uint256 finalReactorDepositToken = mockToken.balanceOf(address(reactor));
        console.log("Final reactor balance:", finalReactorDepositToken);
        assertEq(
            finalReactorDepositToken,
            initialReactorDepositToken + expectedOutput,
            "Reactor should have received the correct amount of deposit tokens"
        );

        // Verify the output amount from the swap
        assertEq(outputAmount, expectedOutput, "Output amount should match the expected value");

        // Verify the computed expected sats
        uint256 manuallyComputedSats = reactor.getComputedAuctionSats(intent.info.auction);
        console.log("Manually computed sats:", manuallyComputedSats);
        assertEq(expectedSats, manuallyComputedSats, "Expected sats should match manual computation");

        // Expected sats should be within bounds
        assertTrue(expectedSats >= minSats && expectedSats <= maxSats, "Expected sats should be within auction bounds");
    }

    /**
     * @notice Test that swap execution correctly handles router failures
     */
    function test_ExecuteIntentAndSwapRouterFail() public {
        // Use small fixed values that won't cause overflow
        uint256 amount = 5000;
        uint256 minSats = 2000;
        uint256 maxSats = 4000;

        // Set router to fail
        router.setShouldRevert(true);

        // Create signed intent with safe values
        Types.SignedIntent memory intent = createSignedIntent(amount, minSats, maxSats);

        // Create route with swap calldata
        bytes memory routeData = router.encodeSwapCall(amount, address(reactor));
        Types.LiquidityRoute memory route = Types.LiquidityRoute({router: address(router), routeData: routeData});

        // Make sure user has enough tokens for the test
        vm.startPrank(address(this));
        tokenIn.mint(user, amount);
        vm.stopPrank();

        // Execute the intent - should revert
        vm.expectRevert(Errors.RouterCallFailed.selector);
        vm.prank(marketMaker);
        reactor.executeIntentAndSwapSharedTest(route, intent);
    }

    /**
     * @notice Test that swap execution works with different conversion rates
     */
    function test_ExecuteIntentWithDifferentConversionRates() public {
        // Use small fixed values that won't cause overflow
        uint256 amount = 5000;
        uint256 minSats = 2000;
        uint256 maxSats = 4000;

        // Test with a few different rates
        uint32[] memory rates = new uint32[](3);
        rates[0] = 100; // 1%
        rates[1] = 200; // 2%
        rates[2] = 500; // 5%

        for (uint i = 0; i < rates.length; i++) {
            uint32 rate = rates[i];

            // Calculate expected output
            uint256 expectedOutput = (amount * rate) / 10000;

            // Reset state for this iteration - mint fresh tokens each time
            vm.startPrank(address(this));
            tokenIn.mint(user, amount);
            vm.stopPrank();

            // Set router's conversion rate
            router.setConversionRate(rate);

            // Create signed intent with safe values
            Types.SignedIntent memory intent = createSignedIntent(amount, minSats, maxSats);

            // Create route with swap calldata
            bytes memory routeData = router.encodeSwapCall(amount, address(reactor));
            Types.LiquidityRoute memory route = Types.LiquidityRoute({router: address(router), routeData: routeData});

            // Record initial balances
            uint256 initialReactorDepositToken = mockToken.balanceOf(address(reactor));

            // Execute the intent
            vm.prank(marketMaker);
            reactor.executeIntentAndSwapSharedTest(route, intent);

            // Get the swap output from the reactor
            uint256 outputAmount = reactor.lastSwapOutput();

            // Verify output amount
            assertEq(outputAmount, expectedOutput, "Output amount should match the expected value");

            // Verify balances after swap
            // Reactor should have received deposit tokens
            assertEq(
                mockToken.balanceOf(address(reactor)) - initialReactorDepositToken,
                expectedOutput,
                "Reactor should have received the correct amount of deposit tokens"
            );
        }
    }

    /**
     * @notice Fuzz test to verify that executeIntentAndSwapShared correctly processes swaps with various amounts
     * and conversion rates
     * @param amountInput Input value to be bounded to a reasonable amount
     * @param conversionRateInput Input value to be bounded to a reasonable conversion rate
     * @param minSatsInput Input value to be bounded to reasonable min sats
     * @param maxSatsInput Input value to be bounded to reasonable max sats
     */
    function testFuzz_ExecuteIntentAndSwapShared(
        uint64 amountInput,
        uint64 conversionRateInput,
        uint64 minSatsInput,
        uint64 maxSatsInput
    ) public {
        // Strictly bound inputs to prevent any possibility of overflow
        // Use uint64 inputs to naturally limit the range
        uint256 amount = bound(uint256(amountInput), 100, 5_000);
        uint256 conversionRate = bound(uint256(conversionRateInput), 100, 1_000); // 1% to 10%
        uint256 minSats = bound(uint256(minSatsInput), 100, 2_000);

        // Ensure max > min but not by too much to avoid overflows
        uint256 maxSats = bound(uint256(maxSatsInput), minSats + 100, minSats + 2_000);

        // Calculate expected output (with careful bounds to prevent overflow)
        uint256 expectedOutput = (amount * conversionRate) / 10000;

        // Set router's conversion rate
        router.setConversionRate(conversionRate);

        // Create signed intent with bounded values
        Types.SignedIntent memory intent = createSignedIntent(amount, minSats, maxSats);

        // Create route with swap calldata
        bytes memory routeData = router.encodeSwapCall(amount, address(reactor));
        Types.LiquidityRoute memory route = Types.LiquidityRoute({router: address(router), routeData: routeData});

        // Make sure user has enough tokens for the test
        vm.startPrank(address(this));
        tokenIn.mint(user, amount); // Just mint the exact amount needed
        vm.stopPrank();

        // Check initial balances
        uint256 initialUserTokenIn = tokenIn.balanceOf(user);
        uint256 initialReactorDepositToken = mockToken.balanceOf(address(reactor));

        // Execute the intent
        vm.prank(marketMaker);
        uint256 expectedSats = reactor.executeIntentAndSwapSharedTest(route, intent);

        // Get the swap output from the reactor
        uint256 outputAmount = reactor.lastSwapOutput();

        // User should have less tokenIn
        assertEq(
            tokenIn.balanceOf(user),
            initialUserTokenIn - amount,
            "User should have their tokenIn reduced by the swap amount"
        );

        // Verify the output amount from the swap
        assertEq(outputAmount, expectedOutput, "Output amount should match the expected value");

        // Reactor should have received deposit tokens
        assertEq(
            mockToken.balanceOf(address(reactor)),
            initialReactorDepositToken + expectedOutput,
            "Reactor should have received the correct amount of deposit tokens"
        );

        // Verify the computed expected sats
        uint256 manuallyComputedSats = reactor.getComputedAuctionSats(intent.info.auction);
        assertEq(expectedSats, manuallyComputedSats, "Expected sats should match manual computation");

        // Expected sats should be within bounds
        assertTrue(expectedSats >= minSats && expectedSats <= maxSats, "Expected sats should be within auction bounds");
    }
}
