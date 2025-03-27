// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup} from "../utils/RiftTestSetup.t.sol";
import {RiftReactor} from "../../src/RiftReactor.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {EIP712Hashing} from "../../src/libraries/Hashing.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {MockToken} from "../utils/MockToken.sol";
import {ISignatureTransfer} from "uniswap-permit2/src/interfaces/ISignatureTransfer.sol";
import {Test} from "forge-std/src/Test.sol";
import {SP1MockVerifier} from "sp1-contracts/contracts/src/SP1MockVerifier.sol";

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

/**
 * @title RiftReactorUnit
 * @notice This contract tests both the helper functions and the main operational functions of RiftReactor.
 * Tests include:
 *  - Bond calculations
 *  - Auction sats calculations
 *  - Intent execution with/without swaps
 *  - Bond release and penalties
 *  - Withdrawal & penalties
 */
contract RiftReactorUnit is RiftTestSetup {
    using EIP712Hashing for Types.IntentInfo;
    using EIP712Hashing for Types.SignedIntent;

    // Test constants
    uint256 constant DEFAULT_MAX_SATS = 10000;
    uint256 constant DEFAULT_MIN_SATS = 5000;

    // Market maker and users
    address marketMaker;
    address user;

    // Router for swap tests
    MockRouter router;

    // Setup tracking
    bytes32 orderHash;
    Types.SignedIntent signedIntent;

    function setUp() public virtual override {
        super.setUp();

        // Setup additional test accounts
        marketMaker = _randomUniqueAddress();
        user = _randomUniqueAddress();

        // Setup router
        router = new MockRouter(address(mockToken), address(cbBTC));

        // Fund accounts
        vm.startPrank(address(this));
        cbBTC.mint(marketMaker, 1000 * 10 ** 8); // 1000 cbBTC
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
            depositOwnerAddress: depositOwner,
            depositAmount: depositAmount,
            btcPayoutScriptPubKey: _generateBtcPayoutScriptPubKey(),
            depositSalt: bytes32(uint256(123)),
            confirmationBlocks: 6,
            safeBlockLeaf: Types.BlockLeaf({height: 1, blockInfoHash: bytes32(uint256(111))}),
            safeBlockSiblings: new bytes32[](0),
            safeBlockPeaks: new bytes32[](0)
        });

        // Create the auction info
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: uint64(startBlock),
            endBlock: uint64(endBlock),
            minSats: uint64(minSats),
            maxSats: uint64(maxSats)
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
            depositLiquidityParams: depositParams,
            auction: auction,
            permit2TransferInfo: permit2TransferInfo,
            tokenIn: tokenIn,
            nonce: 0
        });

        // Calculate orderHash (in real world this would be signed)
        bytes32 calculatedOrderHash = keccak256(abi.encode(intentInfo));

        // Return the signed intent
        return Types.SignedIntent({info: intentInfo, orderHash: calculatedOrderHash});
    }

    // Helper function to create a liquidity route for testing
    function _createLiquidityRoute(uint256 amount) internal returns (Types.LiquidityRoute memory) {
        bytes memory routeData = router.encodeSwapCall(amount, address(riftReactor));

        return Types.LiquidityRoute({router: address(router), routeData: routeData});
    }

    // -----------------------------
    // Tests for computeBond()
    // -----------------------------

    /**
     * @notice Test that when the calculated bond is below the minimum,
     * the function returns MIN_BOND.
     */
    function testComputeBondBelowMinimum() public view {
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        // thresholdDeposit is the deposit amount that yields exactly MIN_BOND.
        uint256 thresholdDeposit = minBond * bondMultiplier;
        // Use an amount just below threshold to force the computed bond below minimum.
        uint256 depositAmount = thresholdDeposit - 1;
        uint96 bond = riftReactor.computeBond(depositAmount);
        assertEq(bond, minBond, "Bond should be set to MIN_BOND when calculated bond is lower");
    }

    /**
     * @notice Test that when the calculated bond (depositAmount / bondMultiplier)
     * is above the minimum, computeBond returns that computed value.
     */
    function testComputeBondAboveMinimum() public view {
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 thresholdDeposit = minBond * bondMultiplier;
        uint256 extra = 5_000_000;
        // Deposit amount greater than thresholdDeposit yields a computed bond above MIN_BOND.
        uint256 depositAmount = thresholdDeposit + extra;
        uint96 bond = riftReactor.computeBond(depositAmount);
        uint96 expectedBond = uint96(depositAmount / bondMultiplier);
        assertEq(bond, expectedBond, "Bond should equal depositAmount/bondMultiplier when that is above MIN_BOND");
    }

    /**
     * @notice Test the edge case where depositAmount is exactly the threshold.
     * The computed bond should equal MIN_BOND.
     */
    function testComputeBondEdgeCase() public view {
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 depositAmount = minBond * bondMultiplier;
        uint96 bond = riftReactor.computeBond(depositAmount);
        assertEq(bond, minBond, "Bond should exactly equal MIN_BOND at the edge case");
    }

    // -----------------------------
    // Tests for computeAuctionSats()
    // -----------------------------

    /**
     * @notice Test that before the auction starts (current block less than startBlock),
     * computeAuctionSats returns maxSats.
     */
    function testComputeAuctionSatsBeforeStart() public {
        vm.roll(200); // Set block.number to 200.
        uint256 current = block.number;
        uint256 startBlock = current + 10;
        uint256 endBlock = current + 100;
        Types.DutchAuctionInfo memory info = Types.DutchAuctionInfo({
            startBlock: uint64(startBlock),
            endBlock: uint64(endBlock),
            minSats: uint64(DEFAULT_MIN_SATS),
            maxSats: uint64(DEFAULT_MAX_SATS)
        });
        uint256 sats = riftReactor.computeAuctionSats(info);
        assertEq(sats, DEFAULT_MAX_SATS, "Auction sats should equal maxSats before the auction start");
    }

    /**
     * @notice Test that after the auction has ended (current block greater than endBlock),
     * computeAuctionSats returns minSats.
     */
    function testComputeAuctionSatsAfterEnd() public {
        vm.roll(200); // Set block.number to 200.
        uint256 current = block.number;
        uint256 startBlock = current - 100;
        uint256 endBlock = current - 10;
        Types.DutchAuctionInfo memory info = Types.DutchAuctionInfo({
            startBlock: uint64(startBlock),
            endBlock: uint64(endBlock),
            minSats: uint64(DEFAULT_MIN_SATS),
            maxSats: uint64(DEFAULT_MAX_SATS)
        });
        uint256 sats = riftReactor.computeAuctionSats(info);
        assertEq(sats, DEFAULT_MIN_SATS, "Auction sats should equal minSats after the auction end");
    }

    /**
     * @notice Test the linear interpolation of auction sats at the midpoint of the auction period.
     */
    function testComputeAuctionSatsMiddle() public {
        vm.roll(1000); // Set block.number to 1000.
        uint256 current = block.number;
        uint256 startBlock = current - 50; // Started 50 blocks ago
        uint256 duration = 100;
        uint256 endBlock = startBlock + duration; // Will end 50 blocks from now
        Types.DutchAuctionInfo memory info = Types.DutchAuctionInfo({
            startBlock: uint64(startBlock),
            endBlock: uint64(endBlock),
            minSats: uint64(DEFAULT_MIN_SATS),
            maxSats: uint64(DEFAULT_MAX_SATS)
        });

        // Calculate the expected reduction in sats at midpoint (50% of the way through)
        uint256 satsDifference = DEFAULT_MAX_SATS - DEFAULT_MIN_SATS;
        uint256 expectedSats = DEFAULT_MAX_SATS - (satsDifference / 2);

        uint256 sats = riftReactor.computeAuctionSats(info);
        assertEq(sats, expectedSats, "Auction sats should be correctly interpolated at the midpoint");
    }

    // --------------------------
    // Tests for executeIntent()
    // --------------------------

    /**
     * @notice Test that executeIntent correctly handles a direct cbBTC deposit
     */
    function testExecuteIntent() public {
        uint256 depositAmount = 1_000_000; // 1 cbBTC unit
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Create intent for direct cbBTC deposit
        Types.SignedIntent memory intent = _createSignedIntent(
            depositAmount,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );

        // Record initial balances
        uint256 initialMMBalance = cbBTC.balanceOf(marketMaker);

        // Execute as market maker
        vm.startPrank(marketMaker);
        riftReactor.executeIntent(intent);
        vm.stopPrank();

        // Calculate expected bond
        uint96 expectedBond = riftReactor.computeBond(depositAmount);

        // Verify bond was deducted from MM
        assertEq(
            cbBTC.balanceOf(marketMaker),
            initialMMBalance - expectedBond,
            "Market maker should have bond deducted"
        );

        // Verify bond record is correct
        Types.BondedSwap memory bond = riftReactor.swapBonds(intent.orderHash);
        assertEq(bond.marketMaker, marketMaker, "Bond should be recorded to the correct market maker");
        assertEq(bond.bond, expectedBond, "Bond amount should match computed value");
        assertEq(bond.endBlock, endBlock, "Bond end block should match auction end block");

        // Verify nonce was incremented
        assertEq(riftReactor.intentNonce(user), 1, "Nonce should be incremented");
    }

    /**
     * @notice Test that executeIntent reverts with invalid nonce
     */
    function testExecuteIntentInvalidNonce() public {
        uint256 depositAmount = 1_000_000; // 1 cbBTC unit
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Create intent for direct cbBTC deposit but with invalid nonce
        Types.SignedIntent memory intent = _createSignedIntent(
            depositAmount,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );
        intent.info.nonce = 1; // Invalid nonce

        // Execute as market maker - should revert
        vm.startPrank(marketMaker);
        vm.expectRevert(Errors.InvalidNonce.selector);
        riftReactor.executeIntent(intent);
        vm.stopPrank();
    }

    // ---------------------------------
    // Tests for executeIntentWithSwap()
    // ---------------------------------

    /**
     * @notice Test that executeIntentWithSwap correctly handles a swap
     */
    function testExecuteIntentWithSwap() public {
        uint256 depositAmount = 1_000_000; // 1 unit of input token
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Mint more cbBTC for the router to handle the swap
        cbBTC.mint(address(router), 10_000_000);

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

        // Verify bond was deducted from MM
        assertEq(
            cbBTC.balanceOf(marketMaker),
            initialMMBalance - expectedBond,
            "Market maker should have bond deducted"
        );

        // Verify tokens were transferred from user
        assertEq(mockToken.balanceOf(user), initialUserBalance - depositAmount, "User's tokens should be transferred");

        // Verify bond record is correct
        Types.BondedSwap memory bond = riftReactor.swapBonds(intent.orderHash);
        assertEq(bond.marketMaker, marketMaker, "Bond should be recorded to the correct market maker");
        assertEq(bond.bond, expectedBond, "Bond amount should match computed value");

        // Verify nonce was incremented
        assertEq(riftReactor.intentNonce(user), 1, "Nonce should be incremented");
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

        // Mint some cbBTC for the router
        cbBTC.mint(address(router), 10_000);

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

    /**
     * @notice Test executeIntentWithSwap with overwrite
     */
    function testExecuteIntentWithSwapOverwrite() public {
        uint256 depositAmount = 1_000_000; // 1 unit of input token
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Mint more cbBTC for the router to handle the swap
        cbBTC.mint(address(router), 10_000_000);

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

        // Create an empty vault for overwrite
        Types.DepositVault memory emptyVault = Types.DepositVault({
            vaultIndex: 1,
            depositTimestamp: uint64(block.timestamp),
            depositAmount: 0,
            depositFee: 0,
            expectedSats: 0,
            btcPayoutScriptPubKey: bytes22(0),
            specifiedPayoutAddress: address(0),
            ownerAddress: address(0),
            salt: bytes32(0),
            confirmationBlocks: 0,
            attestedBitcoinBlockHeight: 0
        });

        // Record initial balances
        uint256 initialMMBalance = cbBTC.balanceOf(marketMaker);
        uint256 initialUserBalance = mockToken.balanceOf(user);

        // Execute as market maker
        vm.startPrank(marketMaker);
        riftReactor.executeIntentWithSwap(route, intent, emptyVault);
        vm.stopPrank();

        // Calculate expected bond
        uint96 expectedBond = riftReactor.computeBond(depositAmount);

        // Verify bond was deducted from MM
        assertEq(
            cbBTC.balanceOf(marketMaker),
            initialMMBalance - expectedBond,
            "Market maker should have bond deducted"
        );

        // Verify tokens were transferred from user
        assertEq(mockToken.balanceOf(user), initialUserBalance - depositAmount, "User's tokens should be transferred");

        // Verify bond record is correct
        Types.BondedSwap memory bond = riftReactor.swapBonds(intent.orderHash);
        assertEq(bond.marketMaker, marketMaker, "Bond should be recorded to the correct market maker");
        assertEq(bond.bond, expectedBond, "Bond amount should match computed value");

        // Verify nonce was incremented
        assertEq(riftReactor.intentNonce(user), 1, "Nonce should be incremented");
    }

    // --------------------------
    // Tests for releaseAndFree()
    // --------------------------

    /**
     * @notice Test releaseAndFree for bond release
     */
    function testReleaseAndFree() public {
        // First, execute an intent
        uint256 depositAmount = 1_000_000; // 1 cbBTC unit
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Create and execute intent
        Types.SignedIntent memory intent = _createSignedIntent(
            depositAmount,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );

        vm.startPrank(marketMaker);
        riftReactor.executeIntent(intent);
        vm.stopPrank();

        // Record balance after bond is taken
        uint256 mmBalanceAfterBond = cbBTC.balanceOf(marketMaker);
        uint96 bondAmount = riftReactor.computeBond(depositAmount);

        // Create release params
        Types.ReleaseLiquidityParams[] memory releaseParams = new Types.ReleaseLiquidityParams[](1);
        releaseParams[0] = Types.ReleaseLiquidityParams({
            orderHash: intent.orderHash,
            swap: Types.ProposedSwap({
                swapIndex: 0,
                state: Types.SwapState.Proved,
                swapBitcoinTxid: bytes32(0),
                bitcoinBlockHash: bytes32(0),
                totalSwapAmount: 0,
                totalSwapFee: 0,
                totalSwapOutput: 0,
                specifiedPayoutAddress: address(0),
                depositVaultIndex: 0
            }),
            swapBlockChainwork: 0,
            swapBlockHeight: 0,
            bitcoinSwapBlockSiblings: new bytes32[](0),
            bitcoinSwapBlockPeaks: new bytes32[](0),
            utilizedVault: Types.DepositVault({
                vaultIndex: 0,
                depositTimestamp: 0,
                depositAmount: 0,
                depositFee: 0,
                expectedSats: 0,
                btcPayoutScriptPubKey: bytes22(0),
                specifiedPayoutAddress: address(0),
                ownerAddress: address(0),
                salt: bytes32(0),
                confirmationBlocks: 0,
                attestedBitcoinBlockHeight: 0
            }),
            tipBlockHeight: 0
        });

        // Release the bond
        riftReactor.releaseAndFree(releaseParams);

        // Verify bond was returned to market maker
        assertEq(
            cbBTC.balanceOf(marketMaker),
            mmBalanceAfterBond + bondAmount,
            "Market maker should receive bond back"
        );

        // Verify bond record was deleted
        Types.BondedSwap memory bond = riftReactor.swapBonds(intent.orderHash);
        assertEq(bond.marketMaker, address(0), "Bond record should be deleted");
    }

    /**
     * @notice Test releaseAndFree for a bond that doesn't exist
     */
    function testReleaseAndFreeBondNotFound() public {
        // Create bogus release params with a random hash
        bytes32 nonExistentOrderHash = bytes32(uint256(123456));

        Types.ReleaseLiquidityParams[] memory releaseParams = new Types.ReleaseLiquidityParams[](1);
        releaseParams[0] = Types.ReleaseLiquidityParams({
            orderHash: nonExistentOrderHash,
            swap: Types.ProposedSwap({
                swapIndex: 0,
                state: Types.SwapState.Proved,
                swapBitcoinTxid: bytes32(0),
                bitcoinBlockHash: bytes32(0),
                totalSwapAmount: 0,
                totalSwapFee: 0,
                totalSwapOutput: 0,
                specifiedPayoutAddress: address(0),
                depositVaultIndex: 0
            }),
            swapBlockChainwork: 0,
            swapBlockHeight: 0,
            bitcoinSwapBlockSiblings: new bytes32[](0),
            bitcoinSwapBlockPeaks: new bytes32[](0),
            utilizedVault: Types.DepositVault({
                vaultIndex: 0,
                depositTimestamp: 0,
                depositAmount: 0,
                depositFee: 0,
                expectedSats: 0,
                btcPayoutScriptPubKey: bytes22(0),
                specifiedPayoutAddress: address(0),
                ownerAddress: address(0),
                salt: bytes32(0),
                confirmationBlocks: 0,
                attestedBitcoinBlockHeight: 0
            }),
            tipBlockHeight: 0
        });

        // Attempt to release - should revert
        vm.expectRevert(Errors.BondNotFoundOrAlreadyReleased.selector);
        riftReactor.releaseAndFree(releaseParams);
    }

    // ------------------------------
    // Tests for withdrawAndPenalize()
    // ------------------------------

    /**
     * @notice Test withdrawAndPenalize for bond slashing
     */
    function testWithdrawAndPenalize() public {
        // First, execute an intent
        uint256 depositAmount = 1_000_000; // 1 cbBTC unit
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Create and execute intent
        Types.SignedIntent memory intent = _createSignedIntent(
            depositAmount,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );

        vm.startPrank(marketMaker);
        riftReactor.executeIntent(intent);
        vm.stopPrank();

        // Record balances after bond is taken
        uint256 mmBalanceAfterBond = cbBTC.balanceOf(marketMaker);
        uint96 bondAmount = riftReactor.computeBond(depositAmount);
        uint256 initialSlashedFees = riftReactor.slashedBondFees();

        // Move past the auction end time
        vm.roll(endBlock + 1);

        // Penalize the market maker
        riftReactor.withdrawAndPenalize(intent.orderHash);

        // Calculate expected penalty and refund
        uint96 penalty = (bondAmount * riftReactor.SLASH_FEE_BIPS()) / 10000;
        uint96 refundAmount = bondAmount - penalty;

        // Verify market maker received refund
        assertEq(
            cbBTC.balanceOf(marketMaker),
            mmBalanceAfterBond + refundAmount,
            "Market maker should receive partial bond back"
        );

        // Verify penalty was recorded
        assertEq(
            riftReactor.slashedBondFees() - initialSlashedFees,
            penalty,
            "Penalty should be recorded in slashedBondFees"
        );

        // Verify bond record was deleted
        Types.BondedSwap memory bond = riftReactor.swapBonds(intent.orderHash);
        assertEq(bond.marketMaker, address(0), "Bond record should be deleted");
    }

    /**
     * @notice Test withdrawAndPenalize before auction ends
     */
    function testWithdrawAndPenalizeBeforeAuctionEnd() public {
        // First, execute an intent
        uint256 depositAmount = 1_000_000; // 1 cbBTC unit
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Create and execute intent
        Types.SignedIntent memory intent = _createSignedIntent(
            depositAmount,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );

        vm.startPrank(marketMaker);
        riftReactor.executeIntent(intent);
        vm.stopPrank();

        // Try to penalize before auction ends - should revert
        vm.expectRevert(Errors.AuctionNotEnded.selector);
        riftReactor.withdrawAndPenalize(intent.orderHash);
    }

    /**
     * @notice Test withdrawAndPenalize for a bond that doesn't exist
     */
    function testWithdrawAndPenalizeBondNotFound() public {
        // Create a non-existent order hash
        bytes32 nonExistentOrderHash = bytes32(uint256(123456));

        // Try to penalize - should revert
        vm.expectRevert(Errors.BondNotFoundOrAlreadyReleased.selector);
        riftReactor.withdrawAndPenalize(nonExistentOrderHash);
    }

    // ------------------------------
    // Tests for Multiple Operations
    // ------------------------------

    /**
     * @notice Test the full lifecycle: execute, then release
     */
    function testFullLifecycleExecuteAndRelease() public {
        // First, execute an intent
        uint256 depositAmount = 1_000_000; // 1 cbBTC unit
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Create and execute intent
        Types.SignedIntent memory intent = _createSignedIntent(
            depositAmount,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );

        vm.startPrank(marketMaker);
        riftReactor.executeIntent(intent);
        vm.stopPrank();

        uint96 bondAmount = riftReactor.computeBond(depositAmount);
        uint256 mmBalanceAfterExecution = cbBTC.balanceOf(marketMaker);

        // Create release params
        Types.ReleaseLiquidityParams[] memory releaseParams = new Types.ReleaseLiquidityParams[](1);
        releaseParams[0] = Types.ReleaseLiquidityParams({
            orderHash: intent.orderHash,
            swap: Types.ProposedSwap({
                swapIndex: 0,
                state: Types.SwapState.Proved,
                swapBitcoinTxid: bytes32(0),
                bitcoinBlockHash: bytes32(0),
                totalSwapAmount: 0,
                totalSwapFee: 0,
                totalSwapOutput: 0,
                specifiedPayoutAddress: address(0),
                depositVaultIndex: 0
            }),
            swapBlockChainwork: 0,
            swapBlockHeight: 0,
            bitcoinSwapBlockSiblings: new bytes32[](0),
            bitcoinSwapBlockPeaks: new bytes32[](0),
            utilizedVault: Types.DepositVault({
                vaultIndex: 0,
                depositTimestamp: 0,
                depositAmount: 0,
                depositFee: 0,
                expectedSats: 0,
                btcPayoutScriptPubKey: bytes22(0),
                specifiedPayoutAddress: address(0),
                ownerAddress: address(0),
                salt: bytes32(0),
                confirmationBlocks: 0,
                attestedBitcoinBlockHeight: 0
            }),
            tipBlockHeight: 0
        });

        // Release the bond
        riftReactor.releaseAndFree(releaseParams);

        // Verify market maker received bond back fully
        assertEq(
            cbBTC.balanceOf(marketMaker),
            mmBalanceAfterExecution + bondAmount,
            "Market maker should receive full bond back"
        );
    }

    /**
     * @notice Test the full lifecycle: execute, then penalize
     */
    function testFullLifecycleExecuteAndPenalize() public {
        // First, execute an intent
        uint256 depositAmount = 1_000_000; // 1 cbBTC unit
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000; // 0.9 BTC in sats
        uint256 maxSats = 1_000_000; // 1 BTC in sats

        // Create and execute intent
        Types.SignedIntent memory intent = _createSignedIntent(
            depositAmount,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );

        vm.startPrank(marketMaker);
        riftReactor.executeIntent(intent);
        vm.stopPrank();

        uint96 bondAmount = riftReactor.computeBond(depositAmount);
        uint256 mmBalanceAfterExecution = cbBTC.balanceOf(marketMaker);
        uint256 initialSlashedFees = riftReactor.slashedBondFees();

        // Move past auction end
        vm.roll(endBlock + 1);

        // Penalize the market maker
        riftReactor.withdrawAndPenalize(intent.orderHash);

        // Calculate expected penalty and refund
        uint96 penalty = (bondAmount * riftReactor.SLASH_FEE_BIPS()) / 10000;
        uint96 refundAmount = bondAmount - penalty;

        // Verify market maker received partial refund
        assertEq(
            cbBTC.balanceOf(marketMaker),
            mmBalanceAfterExecution + refundAmount,
            "Market maker should receive partial bond back"
        );

        // Verify penalty was recorded
        assertEq(
            riftReactor.slashedBondFees() - initialSlashedFees,
            penalty,
            "Penalty should be recorded in slashedBondFees"
        );
    }

    /**
     * @notice Test with multiple intents from same user (nonce handling)
     */
    function testMultipleIntentsFromSameUser() public {
        // Execute first intent
        uint256 depositAmount1 = 1_000_000; // 1 cbBTC unit
        uint256 startBlock = block.number;
        uint256 endBlock = block.number + 100;
        uint256 minSats = 900_000;
        uint256 maxSats = 1_000_000;

        Types.SignedIntent memory intent1 = _createSignedIntent(
            depositAmount1,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );

        vm.startPrank(marketMaker);
        riftReactor.executeIntent(intent1);
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(riftReactor.intentNonce(user), 1, "Nonce should be incremented after first intent");

        // Execute second intent (with updated nonce)
        uint256 depositAmount2 = 2_000_000; // 2 cbBTC units

        Types.SignedIntent memory intent2 = _createSignedIntent(
            depositAmount2,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );
        intent2.info.nonce = 1; // Update nonce

        vm.startPrank(marketMaker);
        riftReactor.executeIntent(intent2);
        vm.stopPrank();

        // Verify nonce was incremented again
        assertEq(riftReactor.intentNonce(user), 2, "Nonce should be incremented after second intent");

        // Try with incorrect nonce - should fail
        Types.SignedIntent memory intent3 = _createSignedIntent(
            depositAmount1,
            startBlock,
            endBlock,
            minSats,
            maxSats,
            user,
            address(cbBTC)
        );
        intent3.info.nonce = 0; // Incorrect nonce

        vm.startPrank(marketMaker);
        vm.expectRevert(Errors.InvalidNonce.selector);
        riftReactor.executeIntent(intent3);
        vm.stopPrank();
    }

    // Add a helper function to expose withdrawLiquidity if needed
    // function withdrawLiquidityPublic(Types.DepositVault memory vault) external {
    //     exchange.withdrawLiquidity(vault);
    // }
}
