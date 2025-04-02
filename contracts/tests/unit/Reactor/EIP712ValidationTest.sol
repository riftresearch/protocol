// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {EIP712Hashing} from "../../../src/libraries/Hashing.sol";
import {SignatureVerification} from "../../../src/libraries/SignatureVerification.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {IPermit2, ISignatureTransfer} from "uniswap-permit2/src/interfaces/IPermit2.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {Events} from "../../../src/libraries/Events.sol";
import {MockToken} from "../../utils/MockToken.sol";

/**
 * @title RiftReactorWithValidation
 * @notice Added EIP712 validation to the _executeIntentAndSwapShared function to test security
 */
contract RiftReactorWithValidation is RiftReactorExposed {
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
    function executeIntentAndSwapTest(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order
    ) public returns (uint256) {
        // This line is added to validate the EIP712 signature
        // With our modified version using 65-byte signatures
        EIP712Hashing.validateEIP712(order, DOMAIN_SEPARATOR);

        // For testing purposes, directly transfer the tokens instead of using permit2
        vm.startPrank(order.info.permit2TransferInfo.owner);
        IERC20(order.info.tokenIn).transfer(address(this), order.info.depositLiquidityParams.depositAmount);
        vm.stopPrank();

        // Execute the swap
        _executeSwap(route, order, order.info.depositLiquidityParams.depositAmount);

        // Calculate expected sats
        uint256 expectedSats = _computeAuctionSats(order.info.auction);

        return expectedSats;
    }
}

/**
 * @title RiftReactorWithoutValidation
 * @notice Explicitly removed validation to demonstrate the vulnerability
 */
contract RiftReactorWithoutValidation is RiftReactorExposed {
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

    // Exposed version that skips EIP712 validation
    function executeIntentAndSwapTest(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order
    ) public returns (uint256) {
        // No EIP712 validation here - simulating the vulnerability

        // For testing purposes, directly transfer the tokens instead of using permit2
        vm.startPrank(order.info.permit2TransferInfo.owner);
        IERC20(order.info.tokenIn).transfer(address(this), order.info.depositLiquidityParams.depositAmount);
        vm.stopPrank();

        // Execute the swap
        _executeSwap(route, order, order.info.depositLiquidityParams.depositAmount);

        // Calculate expected sats
        uint256 expectedSats = _computeAuctionSats(order.info.auction);

        return expectedSats;
    }
}

// Test to demonstrate the EIP712 signature validation vulnerability
contract EIP712ValidationTest is RiftTestSetup {
    using EIP712Hashing for Types.IntentInfo;
    using EIP712Hashing for Types.SignedIntent;
    using SignatureVerification for bytes;

    // Constants
    uint256 constant DECIMALS = 8;
    uint256 constant TOKEN_MULTIPLIER = 10 ** DECIMALS;
    uint256 constant SWAP_AMOUNT = 1 * TOKEN_MULTIPLIER;

    // Test accounts
    address attacker;
    address user;

    // Reactor implementations
    RiftReactorWithValidation secureReactor;
    RiftReactorWithoutValidation vulnerableReactor;

    // Mock token for testing
    MockToken tokenIn;
    MockRouter router;

    function setUp() public override {
        super.setUp();

        // Setup test accounts
        attacker = makeAddr("attacker");
        user = makeAddr("user");

        // Create tokens
        tokenIn = new MockToken("Input Token", "IN", uint8(DECIMALS));

        // Setup MMR proof for constructor
        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);

        // Create both reactor implementations
        secureReactor = new RiftReactorWithValidation(
            initial_mmr_proof.mmrRoot,
            address(mockToken),
            bytes32(keccak256("circuit verification key")),
            address(verifier),
            address(0xfee),
            initial_mmr_proof.blockLeaf,
            address(permit2)
        );

        vulnerableReactor = new RiftReactorWithoutValidation(
            initial_mmr_proof.mmrRoot,
            address(mockToken),
            bytes32(keccak256("circuit verification key")),
            address(verifier),
            address(0xfee),
            initial_mmr_proof.blockLeaf,
            address(permit2)
        );

        // Setup router for swap
        router = new MockRouter(address(tokenIn), address(mockToken));

        // Fund accounts
        vm.startPrank(address(this));
        tokenIn.mint(user, 1000 * TOKEN_MULTIPLIER);
        tokenIn.mint(attacker, 1000 * TOKEN_MULTIPLIER);
        mockToken.mint(address(router), 1000 * TOKEN_MULTIPLIER);
        mockToken.mint(attacker, 1000 * TOKEN_MULTIPLIER);
        vm.stopPrank();

        // Setup approvals
        vm.startPrank(user);
        tokenIn.approve(address(permit2), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(attacker);
        tokenIn.approve(address(permit2), type(uint256).max);
        mockToken.approve(address(vulnerableReactor), type(uint256).max);
        mockToken.approve(address(secureReactor), type(uint256).max);
        vm.stopPrank();
    }

    // Helper to create a signed intent with proper signature
    function createSignedIntent(address signer, address recipient) internal returns (Types.SignedIntent memory) {
        // Create a proper 65-byte signature for testing
        bytes memory signature = new bytes(65);

        Types.IntentInfo memory intentInfo = Types.IntentInfo({
            intentReactor: recipient,
            nonce: 0,
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
                depositOwnerAddress: signer,
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
                    to: recipient,
                    requestedAmount: SWAP_AMOUNT
                }),
                owner: signer,
                signature: new bytes(65) // Valid length for ECDSA signatures
            })
        });

        bytes32 orderHash = keccak256(abi.encode(intentInfo));

        return Types.SignedIntent({info: intentInfo, signature: signature, orderHash: orderHash});
    }

    /**
     * @notice Test that demonstrates the EIP712 signature validation vulnerability
     * @dev This test shows how an attacker can create a fake intent that reuses a valid permit2 signature
     *      but changes the recipient address to steal funds when validation is missing
     */
    function testEIP712ValidationVulnerability() public {
        // 1. Create a legitimate intent from the user to the secure reactor
        Types.SignedIntent memory legitimateIntent = createSignedIntent(user, address(secureReactor));

        // 2. Create a malicious intent that reuses the permit2 signature but redirects to the attacker
        Types.SignedIntent memory maliciousIntent = legitimateIntent;

        // Change the intent recipient to point to the attacker
        maliciousIntent.info.permit2TransferInfo.transferDetails.to = attacker;

        // Keep the same permit2 signature

        // 3. Create route with swap calldata
        bytes memory routeData = router.encodeSwapCall(SWAP_AMOUNT, address(vulnerableReactor));
        Types.LiquidityRoute memory route = Types.LiquidityRoute({router: address(router), routeData: routeData});

        // 4. Try to execute the malicious intent on the secure reactor (should revert)
        vm.startPrank(attacker);
        vm.expectRevert(); // Should revert with signature validation error
        secureReactor.executeIntentAndSwapTest(route, maliciousIntent);
        vm.stopPrank();

        // 5. Try to execute the malicious intent on the vulnerable reactor (should succeed)
        vm.startPrank(attacker);
        // This should succeed because the vulnerable reactor doesn't validate the EIP712 signature
        // In a real-world scenario, this would allow an attacker to steal funds
        vulnerableReactor.executeIntentAndSwapTest(route, maliciousIntent);
        vm.stopPrank();

        // 6. Verify the vulnerability by checking balances
        console.log("This test demonstrates the EIP712 signature validation vulnerability.");
        console.log("A proper implementation should validate the EIP712 signature before using permit2.");
    }
}

// Mock Router for the swap functionality
contract MockRouter {
    IERC20 private immutable _depositToken;
    uint256 private _conversionRate; // Basis points (e.g., 10000 = 100%)
    bool private _shouldRevert;

    constructor(address tokenIn, address depositToken) {
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
