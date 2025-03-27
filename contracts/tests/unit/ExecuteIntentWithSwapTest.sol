// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup} from "../utils/RiftTestSetup.t.sol";
import {RiftReactor} from "../../src/RiftReactor.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {EIP712Hashing} from "../../src/libraries/Hashing.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {ISignatureTransfer} from "uniswap-permit2/src/interfaces/ISignatureTransfer.sol";
import {Test} from "forge-std/src/Test.sol";

// Mock Router/Solver for the swap functionality
contract MockRouter {
    IERC20 private _tokenIn;
    IERC20 private _cbBTC;
    uint256 private _conversionRate; // Basis points (e.g., 9800 = 98%)

    constructor(address tokenIn, address cbBTC) {
        _tokenIn = IERC20(tokenIn);
        _cbBTC = IERC20(cbBTC);
        _conversionRate = 9800; // Default 98% conversion rate
    }

    // Function to set conversion rate (basis points)
    function setConversionRate(uint256 rate) external {
        _conversionRate = rate;
    }

    // This function will be called via `call` with routeData
    function swap(uint256 amountIn, address recipient) external returns (uint256) {
        // Transfer input tokens from msg.sender
        require(_tokenIn.transferFrom(msg.sender, address(this), amountIn), "Transfer failed");

        // Calculate output amount with conversion rate
        uint256 amountOut = (amountIn * _conversionRate) / 10000;

        // Transfer cbBTC to recipient
        require(_cbBTC.transfer(recipient, amountOut), "Output transfer failed");

        return amountOut;
    }

    // Function to encode swap call data for testing
    function encodeSwapCall(uint256 amountIn, address recipient) external pure returns (bytes memory) {
        return abi.encodeWithSelector(this.swap.selector, amountIn, recipient);
    }
}

contract ExecuteIntentWithSwapTest is RiftTestSetup {
    using EIP712Hashing for Types.IntentInfo;
    using EIP712Hashing for Types.SignedIntent;

    // Market maker and users
    address marketMaker;
    address user;

    // Router for swap tests
    MockRouter router;

    function setUp() public virtual override {
        super.setUp();

        // Setup additional test accounts
        marketMaker = makeAddr("marketMaker");
        user = makeAddr("user");

        // Setup router
        router = new MockRouter(address(mockToken), address(cbBTC));

        // Fund accounts
        vm.startPrank(address(this));
        cbBTC.mint(marketMaker, 1000 * 10 ** 8); // 1000 cbBTC
        cbBTC.mint(address(router), 10_000_000); // Add cbBTC to router for swap
        mockToken.mint(user, 10000 * 10 ** 6); // 10,000 token units
        vm.stopPrank();

        // Setup approvals
        vm.startPrank(user);
        mockToken.approve(address(permit2), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(marketMaker);
        cbBTC.approve(address(riftReactor), type(uint256).max);
        vm.stopPrank();
    }

    // Helper function to create a signed intent for testing
    function _createSignedIntent(
        uint256 depositAmount,
        uint256 startBlock,
        uint256 endBlock,
        uint256 minSats,
        uint256 maxSats,
        address depositOwner,
        address tokenIn
    ) internal returns (Types.SignedIntent memory intent) {
        // Create the deposit params
        Types.ReactorDepositLiquidityParams memory depositParams = Types.ReactorDepositLiquidityParams({
            depositAmount: depositAmount,
            depositSalt: bytes32(uint256(123)),
            depositOwnerAddress: depositOwner,
            btcPayoutScriptPubKey: _generateBtcPayoutScriptPubKey(),
            confirmationBlocks: 6,
            safeBlockLeaf: Types.BlockLeaf({blockHash: bytes32(uint256(111)), height: 1, cumulativeChainwork: 1}),
            safeBlockSiblings: new bytes32[](0),
            safeBlockPeaks: new bytes32[](0)
        });

        // Create the auction info
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: minSats,
            maxSats: maxSats
        });

        // Create Permit2 transfer info
        ISignatureTransfer.PermitTransferFrom memory permitTransferFrom = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: tokenIn, amount: depositAmount}),
            nonce: 0,
            deadline: block.timestamp + 3600
        });

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({to: address(riftReactor), requestedAmount: depositAmount});

        Types.Permit2TransferInfo memory permit2TransferInfo = Types.Permit2TransferInfo({
            permitTransferFrom: permitTransferFrom,
            transferDetails: transferDetails,
            owner: depositOwner,
            signature: bytes("dummy_signature") // Mock signature for testing
        });

        // Create the intent info
        Types.IntentInfo memory intentInfo = Types.IntentInfo({
            intentReactor: address(riftReactor),
            nonce: 0,
            tokenIn: tokenIn,
            auction: auction,
            depositLiquidityParams: depositParams,
            permit2TransferInfo: permit2TransferInfo
        });

        // Calculate orderHash (in real world this would be signed)
        bytes32 calculatedOrderHash = keccak256(abi.encode(intentInfo));

        // Return the signed intent
        return
            Types.SignedIntent({info: intentInfo, signature: bytes("dummy_signature"), orderHash: calculatedOrderHash});
    }

    // Helper function to create a liquidity route for testing
    function _createLiquidityRoute(uint256 amount) internal returns (Types.LiquidityRoute memory) {
        bytes memory routeData = router.encodeSwapCall(amount, address(riftReactor));
        return Types.LiquidityRoute({router: address(router), routeData: routeData});
    }

    /**
     * @notice Test that executeIntentWithSwap correctly handles a swap
     */
    function testExecuteIntentWithSwap() public {
        uint256 depositAmount = 1_000_000; // 1 unit of input token
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Create intent with mockToken as input
        Types.SignedIntent memory intent = _createSignedIntent(
            depositAmount,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(mockToken)
        );

        // Create liquidity route
        Types.LiquidityRoute memory route = _createLiquidityRoute(depositAmount);

        // Record initial balances
        uint256 initialMMBalance = cbBTC.balanceOf(marketMaker);
        uint256 initialUserBalance = mockToken.balanceOf(user);

        // Execute as market maker
        vm.startPrank(marketMaker);
        riftReactor.executeIntentWithSwap(route, intent);
        vm.stopPrank();

        // Calculate expected bond
        uint96 expectedBond = riftReactor.computeBond(depositAmount);

        // Verify tokens were transferred from user
        assertEq(mockToken.balanceOf(user), initialUserBalance - depositAmount, "User's tokens should be transferred");

        // Verify cbBTC balance reduced by bond amount
        assertEq(
            cbBTC.balanceOf(marketMaker),
            initialMMBalance - expectedBond,
            "Market maker should have bond deducted"
        );

        // Verify nonce was incremented
        assertEq(riftReactor.intentNonce(user), 1, "Nonce should be incremented");

        // We verify the bond was recorded by the fact the function executed successfully
        // and the cbBTC transfer amount matches the expected bond amount
    }

    /**
     * @notice Test executeIntentWithSwap when router returns insufficient cbBTC
     */
    function testExecuteIntentWithSwapInsufficientCbBTC() public {
        uint256 depositAmount = 1_000_000; // 1 unit of input token
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Set very low conversion rate to simulate insufficient output
        router.setConversionRate(100); // 1% conversion rate

        // Create intent with mockToken as input
        Types.SignedIntent memory intent = _createSignedIntent(
            depositAmount,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(mockToken)
        );

        // Create liquidity route
        Types.LiquidityRoute memory route = _createLiquidityRoute(depositAmount);

        // Execute as market maker - should revert
        vm.startPrank(marketMaker);
        vm.expectRevert(Errors.InsufficientCbBTC.selector);
        riftReactor.executeIntentWithSwap(route, intent);
        vm.stopPrank();
    }
}
