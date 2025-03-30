// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

// import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
// import {Types} from "../../../src/libraries/Types.sol";
// import {Errors} from "../../../src/libraries/Errors.sol";
// import {EIP712Hashing} from "../../../src/libraries/Hashing.sol";
// import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
// import {IPermit2, ISignatureTransfer} from "uniswap-permit2/src/interfaces/IPermit2.sol";
// import {Test} from "forge-std/src/Test.sol";
// import {console} from "forge-std/src/console.sol";
// import {MockToken} from "../../utils/MockToken.sol";
// import {Constants} from "../../../src/libraries/Constants.sol";
// import {RiftUtils} from "../../../src/libraries/RiftUtils.sol";
// import {VaultLib} from "../../../src/libraries/VaultLib.sol";

// // Enhanced exposed contract to include the functions we need to test
// contract RiftReactorExposedForOverwriteTests is RiftReactorExposed {
//     constructor(
//         bytes32 _mmrRoot,
//         address _depositToken,
//         bytes32 _circuitVerificationKey,
//         address _verifier,
//         address _feeRouter,
//         Types.BlockLeaf memory _tipBlockLeaf,
//         address _permit2_address
//     )
//         RiftReactorExposed(
//             _mmrRoot,
//             _depositToken,
//             _circuitVerificationKey,
//             _verifier,
//             _feeRouter,
//             _tipBlockLeaf,
//             _permit2_address
//         )
//     {}

//     // Helper functions to assist with testing the overwrite functionality
//     function createEmptyVault() public pure returns (Types.DepositVault memory) {
//         return
//             Types.DepositVault({
//                 vaultIndex: 0,
//                 depositTimestamp: 0,
//                 depositAmount: 0,
//                 depositFee: 0,
//                 expectedSats: 0,
//                 btcPayoutScriptPubKey: bytes25(0),
//                 specifiedPayoutAddress: address(0),
//                 ownerAddress: address(0),
//                 salt: bytes32(0),
//                 confirmationBlocks: 0,
//                 attestedBitcoinBlockHeight: 0
//             });
//     }

//     // Helper to create a bond
//     function createBondedSwap(bytes32 orderHash, address marketMaker, uint96 bondAmount, uint256 endBlock) public {
//         swapBonds[orderHash] = Types.BondedSwap({marketMaker: marketMaker, bond: bondAmount, endBlock: endBlock});
//     }

//     // Helper to test validation of an intent
//     function recordIntent(Types.SignedIntent calldata order) public {
//         // This is a simplified version of the _validateBondAndRecord function for testing
//         if (order.info.nonce != intentNonce[order.info.depositLiquidityParams.depositOwnerAddress]) {
//             revert Errors.InvalidNonce();
//         }

//         uint96 requiredBond = _computeBond(order.info.depositLiquidityParams.depositAmount);
//         bytes32 orderId = order.orderHash;

//         // Record the bonded swap
//         swapBonds[orderId] = Types.BondedSwap({
//             marketMaker: msg.sender,
//             bond: requiredBond,
//             endBlock: order.info.auction.endBlock
//         });

//         // For testing, we assume the transferFrom succeeds
//     }

//     // For the overloaded function, expose depositLiquidityWithOverwrite
//     function depositLiquidityWithOverwriteTest(Types.DepositLiquidityWithOverwriteParams memory params) public {
//         _depositLiquidityWithOverwrite(params);
//     }

//     // Add public wrapper for depositLiquidityWithOverwrite
//     function depositLiquidityWithOverwritePublic(Types.DepositLiquidityWithOverwriteParams memory params) public {
//         _depositLiquidityWithOverwrite(params);
//     }

//     // Add public wrapper for withdrawLiquidity
//     function withdrawLiquidityPublic(Types.DepositVault calldata vault) public {
//         _withdrawLiquidity(vault);
//     }

//     // Add public method to access vault commitment
//     function getVaultCommitment(uint256 vaultIndex) external view override returns (bytes32) {
//         return vaultCommitments[vaultIndex];
//     }

//     // Get a bonded swap by order hash
//     function getBondedSwap(bytes32 orderHash) public view returns (Types.BondedSwap memory) {
//         return swapBonds[orderHash];
//     }

//     // Expose the shared functionality for easier testing
//     function executeIntentAndSwapShared(
//         Types.LiquidityRoute calldata route,
//         Types.SignedIntent calldata order
//     ) public returns (uint256) {
//         return _executeIntentAndSwapShared(route, order);
//     }

//     // Skip the permit2 validation for testing
//     function mockPermit2Transfer(address tokenIn, uint256 amount) public {
//         // Just pretend Permit2 transferred the funds already
//     }
// }

// // Mock Router for the swap functionality
// contract MockRouter {
//     IERC20 private immutable _depositToken;
//     uint256 private _conversionRate; // Basis points (e.g., 10000 = 100%)
//     bool private _shouldRevert;

//     constructor(address depositToken) {
//         _depositToken = IERC20(depositToken);
//         _conversionRate = 10000; // Default 100% conversion rate
//         _shouldRevert = false;
//     }

//     // Function to set conversion rate (basis points)
//     function setConversionRate(uint256 rate) external {
//         _conversionRate = rate;
//     }

//     // Function to make the router revert
//     function setShouldRevert(bool shouldRevert) external {
//         _shouldRevert = shouldRevert;
//     }

//     // This function will be called via `call` with routeData
//     function swap(uint256 amountIn, address recipient) external returns (uint256) {
//         if (_shouldRevert) {
//             revert("Mock router reverted");
//         }

//         // Calculate output amount with conversion rate
//         uint256 amountOut = (amountIn * _conversionRate) / 10000;

//         // Transfer depositToken to recipient
//         require(_depositToken.transfer(recipient, amountOut), "Output transfer failed");

//         return amountOut;
//     }

//     // Function to encode swap call data for testing
//     function encodeSwapCall(uint256 amountIn, address recipient) external pure returns (bytes memory) {
//         return abi.encodeWithSelector(this.swap.selector, amountIn, recipient);
//     }
// }

// contract ExecuteIntentWithSwapOverwriteTest is RiftTestSetup {
//     using EIP712Hashing for Types.IntentInfo;
//     using EIP712Hashing for Types.SignedIntent;

//     // Constants
//     uint256 constant DECIMALS = 8;
//     uint256 constant TOKEN_MULTIPLIER = 10 ** DECIMALS;

//     // Token amounts
//     uint256 constant MARKET_MAKER_INITIAL_BALANCE = 10000 * TOKEN_MULTIPLIER; // 10,000 tokens
//     uint256 constant USER_INITIAL_BALANCE = 100000 * TOKEN_MULTIPLIER; // 100,000 tokens
//     uint256 constant SWAP_AMOUNT = 1 * TOKEN_MULTIPLIER; // 1 token

//     // Market maker and users
//     address marketMaker;
//     address user;

//     // Enhanced reactor for testing
//     RiftReactorExposedForOverwriteTests public reactor;

//     // Mock token for input
//     MockToken tokenIn;

//     // Router for swap tests
//     MockRouter router;

//     function setUp() public override {
//         super.setUp();

//         // Setup additional test accounts
//         marketMaker = makeAddr("marketMaker");
//         user = makeAddr("user");

//         // Roll to a known block number to avoid underflows
//         vm.roll(100);
//         console.log("Starting at block number:", block.number);

//         // Create new reactor with enhanced functionality
//         Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
//         reactor = new RiftReactorExposedForOverwriteTests({
//             _mmrRoot: initial_mmr_proof.mmrRoot,
//             _depositToken: address(mockToken),
//             _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
//             _verifier: address(verifier),
//             _feeRouter: address(0xfee),
//             _tipBlockLeaf: initial_mmr_proof.blockLeaf,
//             _permit2_address: address(permit2)
//         });

//         // Setup tokens
//         tokenIn = new MockToken("Input Token", "IN", uint8(DECIMALS));

//         // Setup router
//         router = new MockRouter(address(mockToken));

//         // Fund accounts
//         vm.startPrank(address(this));
//         mockToken.mint(marketMaker, MARKET_MAKER_INITIAL_BALANCE);
//         mockToken.mint(address(router), MARKET_MAKER_INITIAL_BALANCE);
//         mockToken.mint(address(reactor), MARKET_MAKER_INITIAL_BALANCE); // Ensure reactor has mockToken for tests
//         tokenIn.mint(user, USER_INITIAL_BALANCE);
//         tokenIn.mint(address(reactor), SWAP_AMOUNT * 2); // Ensure reactor has tokenIn for tests
//         tokenIn.mint(marketMaker, SWAP_AMOUNT * 10); // Ensure market maker has tokenIn for tests
//         vm.stopPrank();

//         // Setup approvals
//         vm.startPrank(marketMaker);
//         mockToken.approve(address(reactor), type(uint256).max);
//         tokenIn.approve(address(reactor), type(uint256).max);
//         vm.stopPrank();

//         vm.startPrank(user);
//         tokenIn.approve(address(permit2), type(uint256).max);
//         tokenIn.approve(address(reactor), type(uint256).max);
//         vm.stopPrank();

//         // Also approve router to spend reactor's tokens
//         vm.startPrank(address(reactor));
//         tokenIn.approve(address(router), type(uint256).max);
//         vm.stopPrank();

//         // Mock the permit2 contract to allow the tests to run
//         vm.mockCall(
//             address(permit2),
//             abi.encodeWithSignature(
//                 "permitTransferFrom((address,uint256,uint256,uint256),(address,uint256),address,bytes)"
//             ),
//             abi.encode()
//         );

//         console.log("Setup complete");
//         console.log("Market maker token balance:", mockToken.balanceOf(marketMaker));
//         console.log("Router token balance:", mockToken.balanceOf(address(router)));
//         console.log("Reactor token balance:", mockToken.balanceOf(address(reactor)));
//     }

//     function _generateBtcPayoutScriptPubKey2() internal returns (bytes22) {
//         return bytes22(bytes.concat(bytes2(0x0014), keccak256(abi.encode(_random()))));
//     }

//     // Helper to create a signed intent
//     function createSignedIntent(bool validNonce) internal returns (Types.SignedIntent memory) {
//         bytes22 btcPayoutScriptPubKey = _generateBtcPayoutScriptPubKey();

//         bytes32 depositSalt = bytes32(keccak256(abi.encode(_random())));

//         Types.MMRProof memory mmr_proof = _generateFakeBlockMMRProofFFI(0);

//         Types.IntentInfo memory intentInfo = Types.IntentInfo({
//             intentReactor: address(reactor),
//             nonce: validNonce ? 0 : 1, // Use correct or incorrect nonce
//             tokenIn: address(tokenIn),
//             auction: Types.DutchAuctionInfo({
//                 startBlock: block.number,
//                 endBlock: block.number + 100,
//                 minSats: 900_000,
//                 maxSats: 1_000_000
//             }),
//             depositLiquidityParams: Types.ReactorDepositLiquidityParams({
//                 depositAmount: SWAP_AMOUNT,
//                 depositSalt: depositSalt,
//                 depositOwnerAddress: user,
//                 btcPayoutScriptPubKey: btcPayoutScriptPubKey,
//                 confirmationBlocks: 2,
//                 safeBlockLeaf: mmr_proof.blockLeaf,
//                 safeBlockSiblings: mmr_proof.siblings,
//                 safeBlockPeaks: mmr_proof.peaks
//             }),
//             permit2TransferInfo: Types.Permit2TransferInfo({
//                 permitTransferFrom: ISignatureTransfer.PermitTransferFrom({
//                     permitted: ISignatureTransfer.TokenPermissions({token: address(tokenIn), amount: SWAP_AMOUNT}),
//                     nonce: 0,
//                     deadline: block.timestamp + 3600
//                 }),
//                 transferDetails: ISignatureTransfer.SignatureTransferDetails({
//                     to: address(reactor),
//                     requestedAmount: SWAP_AMOUNT
//                 }),
//                 owner: user,
//                 signature: bytes("0x")
//             })
//         });

//         // For test purposes, use a simple hash
//         bytes32 orderHash = keccak256(abi.encode(intentInfo));

//         return
//             Types.SignedIntent({
//                 info: intentInfo,
//                 orderHash: orderHash,
//                 signature: bytes("0x") // Using mock signature
//             });
//     }

//     // Helper to create a liquidity route
//     function createLiquidityRoute() internal view returns (Types.LiquidityRoute memory) {
//         bytes memory routeData = router.encodeSwapCall(SWAP_AMOUNT, address(reactor));
//         return Types.LiquidityRoute({router: address(router), routeData: routeData});
//     }

//     // Helper to create an empty deposit vault for overwriting
//     function createEmptyVault() internal returns (Types.DepositVault memory) {
//         bytes22 btcPayoutScriptPubKey = _generateBtcPayoutScriptPubKey();

//         bytes32 depositSalt = bytes32(keccak256(abi.encode(_random())));

//         // Types.MMRProof memory mmr_proof = _generateFakeBlockMMRProofFFI(0);
//         return
//             Types.DepositVault({
//                 vaultIndex: 123, // Arbitrary index
//                 depositTimestamp: 0,
//                 depositAmount: 0,
//                 depositFee: 0,
//                 expectedSats: 0,
//                 btcPayoutScriptPubKey: btcPayoutScriptPubKey,
//                 specifiedPayoutAddress: address(0),
//                 ownerAddress: address(0),
//                 salt: depositSalt,
//                 confirmationBlocks: 0,
//                 attestedBitcoinBlockHeight: 0
//             });
//     }

//     /// @notice Test the basic path of executeIntentWithSwap with vault overwrite
//     // function testExecuteIntentWithSwapOverwriteBasic() public {
//     function testFuzz_depositLiquidityWithOverwrite(
//         uint256 depositAmount,
//         uint64 expectedSats,
//         uint256 toBeOverwrittendepositAmount,
//         uint64 toBeOverwrittenExpectedSats,
//         bytes32 depositSalt,
//         uint8 confirmationBlocks,
//         uint256
//     ) public {
//         // [0] bound deposit amounts & expected sats
//         depositAmount = bound(depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
//         expectedSats = uint64(bound(expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
//         confirmationBlocks = uint8(bound(confirmationBlocks, Constants.MIN_CONFIRMATION_BLOCKS, type(uint8).max));
//         toBeOverwrittendepositAmount = bound(
//             toBeOverwrittendepositAmount,
//             Constants.MIN_DEPOSIT_AMOUNT,
//             type(uint64).max
//         );
//         toBeOverwrittenExpectedSats = uint64(
//             bound(toBeOverwrittenExpectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max)
//         );

//         // [1] create initial deposit
//         Types.DepositVault memory fullVault = _depositLiquidityWithAssertions(
//             toBeOverwrittendepositAmount,
//             toBeOverwrittenExpectedSats,
//             confirmationBlocks
//         );

//         console.log("calculating lock up period with confirmation blocks", confirmationBlocks);
//         console.log("depositLockupPeriod", RiftUtils.calculateDepositLockupPeriod(confirmationBlocks));

//         // [2] warp and withdraw to empty the vault
//         vm.warp(block.timestamp + RiftUtils.calculateDepositLockupPeriod(confirmationBlocks));
//         vm.recordLogs();
//         reactor.withdrawLiquidityPublic({vault: fullVault});
//         Types.DepositVault memory emptyVault = _extractSingleVaultFromLogs(vm.getRecordedLogs());

//         // [3] burn the USDC withdrawn from the vault
//         mockToken.transfer(address(0), mockToken.balanceOf(address(this)));

//         // [4] prepare for overwrite deposit
//         mockToken.mint(address(this), depositAmount);
//         mockToken.approve(address(reactor), depositAmount);

//         // [5] generate fake tip block mmr proof
//         Types.MMRProof memory mmr_proof = _generateFakeBlockMMRProofFFI(0);

//         // [6] perform overwrite deposit
//         vm.recordLogs();
//         Types.DepositLiquidityWithOverwriteParams memory args = Types.DepositLiquidityWithOverwriteParams({
//             depositParams: Types.DepositLiquidityParams({
//                 depositOwnerAddress: address(this),
//                 specifiedPayoutAddress: address(this),
//                 depositAmount: depositAmount,
//                 expectedSats: expectedSats,
//                 btcPayoutScriptPubKey: _generateBtcPayoutScriptPubKey(),
//                 depositSalt: depositSalt,
//                 confirmationBlocks: confirmationBlocks,
//                 safeBlockLeaf: mmr_proof.blockLeaf,
//                 safeBlockSiblings: mmr_proof.siblings,
//                 safeBlockPeaks: mmr_proof.peaks
//             }),
//             overwriteVault: emptyVault
//         });

//         reactor.depositLiquidityWithOverwritePublic(args);

//         // [6] grab the logs, find the new vault
//         Types.DepositVault memory overwrittenVault = _extractSingleVaultFromLogs(vm.getRecordedLogs());
//         bytes32 commitment = reactor.getVaultCommitment(emptyVault.vaultIndex);

//         // [7] verify "offchain" calculated commitment matches stored vault commitment
//         bytes32 offchainCommitment = VaultLib.hashDepositVault(overwrittenVault);
//         assertEq(offchainCommitment, commitment, "Offchain vault commitment should match");

//         // [8] verify vault index remains the same
//         assertEq(overwrittenVault.vaultIndex, emptyVault.vaultIndex, "Vault index should match original");

//         // [9] verify caller has no balance left
//         assertEq(mockToken.balanceOf(address(this)), 0, "Caller should have no balance left");

//         // [10] verify owner address
//         assertEq(overwrittenVault.ownerAddress, address(this), "Owner address should match");
//         // // Create a signed intent
//         // Types.SignedIntent memory order = createSignedIntent(true);

//         // // Create a liquidity route
//         // Types.LiquidityRoute memory route = createLiquidityRoute();

//         // // Create an empty vault to overwrite
//         // Types.DepositVault memory emptyVault = createEmptyVault();

//         // // Set up for monitoring the intent nonce
//         // uint256 initialNonce = reactor.intentNonce(user);

//         // // Set router to return exactly the required tokens
//         // router.setConversionRate(10000); // 100% conversion rate

//         // // Simulate the market maker actions
//         // vm.startPrank(marketMaker);

//         // // Call the executeIntentWithSwap function with vault overwrite
//         // reactor.executeIntentWithSwap(route, order, emptyVault);

//         // // Verify the nonce was incremented
//         // assertEq(reactor.intentNonce(user), initialNonce + 1, "Intent nonce should be incremented");

//         // vm.stopPrank();
//     }

//     /// @notice Test executeIntentWithSwap with vault overwrite when router fails
//     function testExecuteIntentWithSwapOverwriteRouterFailure() public {
//         // Create a signed intent
//         Types.SignedIntent memory order = createSignedIntent(true);

//         // Set the router to fail
//         router.setShouldRevert(true);
//         Types.LiquidityRoute memory route = createLiquidityRoute();

//         // Create an empty vault to overwrite
//         Types.DepositVault memory emptyVault = createEmptyVault();

//         // Start as market maker
//         vm.startPrank(marketMaker);

//         // Call should revert with RouterCallFailed error
//         vm.expectRevert(Errors.RouterCallFailed.selector);
//         reactor.executeIntentWithSwap(route, order, emptyVault);

//         vm.stopPrank();
//     }

//     /// @notice Test executeIntentWithSwap with vault overwrite when insufficient cbBTC is received
//     function testExecuteIntentWithSwapOverwriteInsufficientOutput() public {
//         // Create a signed intent
//         Types.SignedIntent memory order = createSignedIntent(true);

//         // Set router conversion rate to 50% - will result in insufficient deposit token
//         router.setConversionRate(5000); // 50% conversion rate
//         Types.LiquidityRoute memory route = createLiquidityRoute();

//         // Create an empty vault to overwrite
//         Types.DepositVault memory emptyVault = createEmptyVault();

//         // Start as market maker
//         vm.startPrank(marketMaker);

//         // Call should revert with InsufficientCbBTC error
//         vm.expectRevert(Errors.InsufficientCbBTC.selector);
//         reactor.executeIntentWithSwap(route, order, emptyVault);

//         vm.stopPrank();
//     }

//     /// @notice Test executeIntentWithSwap with invalid vault
//     function testExecuteIntentWithSwapInvalidVault() public {
//         // Create a signed intent
//         Types.SignedIntent memory order = createSignedIntent(true);

//         // Create a liquidity route
//         Types.LiquidityRoute memory route = createLiquidityRoute();

//         // Create a non-empty vault (with deposit amount > 0)
//         Types.DepositVault memory invalidVault = Types.DepositVault({
//             vaultIndex: 123,
//             depositTimestamp: 1,
//             depositAmount: 1000, // Non-zero deposit amount makes this invalid for overwrite
//             depositFee: 0,
//             expectedSats: 0,
//             btcPayoutScriptPubKey: bytes25(0),
//             specifiedPayoutAddress: address(0),
//             ownerAddress: address(0),
//             salt: bytes32(0),
//             confirmationBlocks: 0,
//             attestedBitcoinBlockHeight: 0
//         });

//         // Start as market maker
//         vm.startPrank(marketMaker);

//         // We expect a revert here when trying to overwrite a non-empty vault
//         // The exact error depends on how the overwrite validation is implemented
//         vm.expectRevert(); // Generic revert expectation
//         reactor.executeIntentWithSwap(route, order, invalidVault);

//         vm.stopPrank();
//     }

//     /// @notice Test executeIntentWithSwap with an invalid nonce
//     function testExecuteIntentWithSwapInvalidNonce() public {
//         // Create a signed intent with invalid nonce
//         Types.SignedIntent memory order = createSignedIntent(false);

//         // Create a liquidity route
//         Types.LiquidityRoute memory route = createLiquidityRoute();

//         // Create an empty vault to overwrite
//         Types.DepositVault memory emptyVault = createEmptyVault();

//         // Start as market maker
//         vm.startPrank(marketMaker);

//         // Call should revert with InvalidNonce error
//         vm.expectRevert(Errors.InvalidNonce.selector);
//         reactor.executeIntentWithSwap(route, order, emptyVault);

//         vm.stopPrank();
//     }

//     /// @notice Test executing the same intent twice (nonce mismatch)
//     function testExecuteIntentWithSwapTwice() public {
//         // Create a signed intent
//         Types.SignedIntent memory order = createSignedIntent(true);

//         // Create a liquidity route
//         Types.LiquidityRoute memory route = createLiquidityRoute();

//         // Create an empty vault to overwrite
//         Types.DepositVault memory emptyVault = createEmptyVault();

//         // Set router to return exactly the required tokens
//         router.setConversionRate(10000); // 100% conversion rate

//         // First execution should succeed
//         vm.startPrank(marketMaker);
//         reactor.executeIntentWithSwap(route, order, emptyVault);

//         // Create a new signed intent with the same parameters but wrong nonce
//         Types.SignedIntent memory order2 = createSignedIntent(true); // This will now have nonce 0, but actual nonce is 1

//         // Create a new empty vault for the second attempt
//         Types.DepositVault memory emptyVault2 = createEmptyVault();
//         emptyVault2.vaultIndex = 456; // Different index

//         // Second execution should fail due to nonce increment
//         vm.expectRevert(Errors.InvalidNonce.selector);
//         reactor.executeIntentWithSwap(route, order2, emptyVault2);

//         vm.stopPrank();
//     }
// }
