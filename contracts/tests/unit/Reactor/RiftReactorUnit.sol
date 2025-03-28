// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;
import {RiftTestSetup} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {ISignatureTransfer} from "uniswap-permit2/src/interfaces/ISignatureTransfer.sol";
import {IPermit2} from "uniswap-permit2/src/interfaces/IPermit2.sol";
import {RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {MockToken} from "../../utils/MockToken.sol";

// Enhanced exposed contract to include the functions we need to test
contract RiftReactorExposedEnhanced is RiftReactorExposed {
    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        Types.BlockLeaf memory _tipBlockLeaf,
        address _permit2_adress
    )
        RiftReactorExposed(
            _mmrRoot,
            _depositToken,
            _circuitVerificationKey,
            _verifier,
            _feeRouter,
            _tipBlockLeaf,
            _permit2_adress
        )
    {}

    // Expose _executeSwap for testing
    function executeSwap(
        Types.LiquidityRoute calldata route,
        Types.SignedIntent calldata order,
        uint256 depositAmount
    ) public {
        _executeSwap(route, order, depositAmount);
    }

    // Expose _buildDepositLiquidityParams for testing
    function buildDepositLiquidityParams(
        Types.ReactorDepositLiquidityParams calldata baseParams,
        address specifiedPayoutAddress,
        uint256 expectedSats
    ) public pure returns (Types.DepositLiquidityParams memory params) {
        return _buildDepositLiquidityParams(baseParams, specifiedPayoutAddress, expectedSats);
    }
}

contract RiftReactorUnit is RiftTestSetup {
    // Define default auction parameters for clarity.
    uint256 constant DEFAULT_MAX_SATS = 10000;
    uint256 constant DEFAULT_MIN_SATS = 5000;

    // Enhanced exposed reactor for testing the additional functions
    RiftReactorExposedEnhanced public riftReactorEnhanced;
    MockToken public tokenIn;
    MockRouter public router;

    function setUp() public override {
        super.setUp();

        // Create our enhanced version of the reactor for testing
        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
        riftReactorEnhanced = new RiftReactorExposedEnhanced({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _tipBlockLeaf: initial_mmr_proof.blockLeaf,
            _permit2_adress: address(permit2)
        });

        // Create a mock token to serve as tokenIn for swap tests
        tokenIn = new MockToken("Input Token", "IN", 18);
        tokenIn.mint(address(this), 1_000_000 * 10 ** 18);

        // Create a mock router for swap tests
        router = new MockRouter(address(mockToken));
        mockToken.mint(address(router), 1_000_000 * 10 ** 8);
    }

    // -----------------------------
    // Tests for computeBond()
    // -----------------------------

    /// @notice Test that computeBond returns MIN_BOND when depositAmount yields a bond below the minimum.
    function testComputeBondBelowMinimum() public view {
        // Bond is computed as (depositAmount * BOND_BIPS / 10_000).
        // For BOND_BIPS = 100, this simplifies to depositAmount / 100.
        // To force the computed bond to be below MIN_BOND, choose depositAmount such that:
        //   depositAmount < MIN_BOND * (10_000 / BOND_BIPS)
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 thresholdDeposit = minBond * bondMultiplier;

        uint256 depositAmount = thresholdDeposit - 1;
        uint96 bond = riftReactor.computeBond(depositAmount);
        assertEq(bond, minBond, "Bond should be set to MIN_BOND when calculated bond is lower");
    }

    /// @notice Test that computeBond returns depositAmount/100 when that value is above MIN_BOND.
    function testComputeBondAboveMinimum() public view {
        // For a deposit amount above the threshold, the computed bond is depositAmount / bondMultiplier.
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 thresholdDeposit = minBond * bondMultiplier;

        // Choose depositAmount greater than thresholdDeposit by an extra delta.
        uint256 extra = 5_000_000;
        uint256 depositAmount = thresholdDeposit + extra;
        uint96 bond = riftReactor.computeBond(depositAmount);
        uint96 expectedBond = uint96(depositAmount / bondMultiplier);
        assertEq(bond, expectedBond, "Bond should equal depositAmount/bondMultiplier when that is above MIN_BOND");
    }

    /// @notice Test the edge case where depositAmount / bondMultiplier equals exactly MIN_BOND.
    function testComputeBondEdgeCase() public view {
        // Set depositAmount exactly to thresholdDeposit.
        uint256 minBond = riftReactor.MIN_BOND();
        uint256 bondMultiplier = 10000 / riftReactor.BOND_BIPS();
        uint256 depositAmount = minBond * bondMultiplier;

        uint96 bond = riftReactor.computeBond(depositAmount);
        assertEq(bond, minBond, "Bond should exactly equal MIN_BOND at the edge case");
    }

    // -----------------------------
    // Tests for computeAuctionSats()
    // -----------------------------

    /// @notice Test that computeAuctionSats returns maxSats when current block is before startBlock.
    function testComputeAuctionSatsBeforeStart() public {
        // Roll to a known block number.
        vm.roll(200);
        uint256 current = block.number;
        // Set auction to start in 10 blocks and end in 100 blocks.
        uint256 startBlock = current + 10;
        uint256 endBlock = current + 100;

        Types.DutchAuctionInfo memory info = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: DEFAULT_MIN_SATS,
            maxSats: DEFAULT_MAX_SATS
        });

        // Before the auction start, expect maxSats.
        uint256 sats = riftReactor.computeAuctionSats(info);
        assertEq(sats, DEFAULT_MAX_SATS, "Auction sats should equal maxSats before the auction start");
    }

    /// @notice Test that computeAuctionSats returns minSats when current block is after endBlock.
    function testComputeAuctionSatsAfterEnd() public {
        // Roll to a known block number.
        vm.roll(200);
        uint256 current = block.number;
        // Set auction to have ended in the past.
        uint256 startBlock = current - 100;
        uint256 endBlock = current - 10;

        Types.DutchAuctionInfo memory info = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: DEFAULT_MIN_SATS,
            maxSats: DEFAULT_MAX_SATS
        });

        // After the auction end, expect minSats.
        uint256 sats = riftReactor.computeAuctionSats(info);
        assertEq(sats, DEFAULT_MIN_SATS, "Auction sats should equal minSats after the auction end");
    }

    /// @notice Test that computeAuctionSats returns the correctly interpolated value in the middle of the auction.
    function testComputeAuctionSatsMiddle() public {
        // Roll to a known block number.
        vm.roll(1000);
        uint256 current = block.number;
        // Set an auction period starting in 10 blocks.
        uint256 startBlock = current + 10;
        uint256 duration = 100;
        uint256 endBlock = startBlock + duration;

        Types.DutchAuctionInfo memory info = Types.DutchAuctionInfo({
            startBlock: startBlock,
            endBlock: endBlock,
            minSats: DEFAULT_MIN_SATS,
            maxSats: DEFAULT_MAX_SATS
        });

        // Roll to the midpoint of the auction period.
        uint256 middleBlock = startBlock + (duration / 2);
        vm.roll(middleBlock);

        // Calculate expected value:
        // elapsed = duration/2, diff = (maxSats - minSats).
        // reduction = (maxSats - minSats) * (duration/2) / duration.
        uint256 reduction = ((DEFAULT_MAX_SATS - DEFAULT_MIN_SATS) * (duration / 2)) / duration;
        uint256 expectedSats = DEFAULT_MAX_SATS - reduction;
        uint256 sats = riftReactor.computeAuctionSats(info);
        assertEq(sats, expectedSats, "Auction sats should be correctly interpolated at the midpoint");
    }

    // -----------------------------
    // Tests for _buildDepositLiquidityParams
    // -----------------------------

    /// @notice Test that _buildDepositLiquidityParams correctly maps parameters
    function testBuildDepositLiquidityParams() public view {
        // Create mock data for testing
        address depositOwnerAddress = address(0x123);
        address specifiedPayoutAddress = address(0x456);
        uint256 depositAmount = 1_000_000;
        uint256 expectedSats = 10_000;
        bytes25 btcPayoutScriptPubKey = bytes25(bytes32(keccak256("scriptPubKey")));
        bytes32 depositSalt = keccak256("salt");
        uint8 confirmationBlocks = 3;

        // Create a BlockLeaf for testing
        Types.BlockLeaf memory safeBlockLeaf = Types.BlockLeaf({
            blockHash: bytes32(keccak256("blockHash")),
            height: 100,
            cumulativeChainwork: 1000
        });

        // Create siblings and peaks arrays
        bytes32[] memory safeBlockSiblings = new bytes32[](1);
        safeBlockSiblings[0] = bytes32(keccak256("sibling"));

        bytes32[] memory safeBlockPeaks = new bytes32[](1);
        safeBlockPeaks[0] = bytes32(keccak256("peak"));

        // Create the ReactorDepositLiquidityParams
        Types.ReactorDepositLiquidityParams memory baseParams = Types.ReactorDepositLiquidityParams({
            depositAmount: depositAmount,
            depositSalt: depositSalt,
            depositOwnerAddress: depositOwnerAddress,
            btcPayoutScriptPubKey: btcPayoutScriptPubKey,
            confirmationBlocks: confirmationBlocks,
            safeBlockLeaf: safeBlockLeaf,
            safeBlockSiblings: safeBlockSiblings,
            safeBlockPeaks: safeBlockPeaks
        });

        // Call the function to test
        Types.DepositLiquidityParams memory result = riftReactorEnhanced.buildDepositLiquidityParams(
            baseParams,
            specifiedPayoutAddress,
            expectedSats
        );

        // Verify the result
        assertEq(result.depositOwnerAddress, depositOwnerAddress, "Deposit owner address should match");
        assertEq(result.specifiedPayoutAddress, specifiedPayoutAddress, "Specified payout address should match");
        assertEq(result.depositAmount, depositAmount, "Deposit amount should match");
        assertEq(result.expectedSats, uint64(expectedSats), "Expected sats should match");
        assertEq(
            bytes32(result.btcPayoutScriptPubKey),
            bytes32(btcPayoutScriptPubKey),
            "BTC payout script pubkey should match"
        );
        assertEq(result.depositSalt, depositSalt, "Deposit salt should match");
        assertEq(result.confirmationBlocks, confirmationBlocks, "Confirmation blocks should match");
        assertEq(result.safeBlockLeaf.blockHash, safeBlockLeaf.blockHash, "Safe block hash should match");
        assertEq(result.safeBlockLeaf.height, safeBlockLeaf.height, "Safe block height should match");
        assertEq(
            result.safeBlockLeaf.cumulativeChainwork,
            safeBlockLeaf.cumulativeChainwork,
            "Safe block chainwork should match"
        );
        assertEq(result.safeBlockSiblings[0], safeBlockSiblings[0], "Safe block siblings should match");
        assertEq(result.safeBlockPeaks[0], safeBlockPeaks[0], "Safe block peaks should match");
    }

    // -----------------------------
    // Tests for _executeSwap
    // -----------------------------

    /// @notice Test that _executeSwap correctly executes a swap through a router
    function testExecuteSwap() public {
        // Set up the router and balances
        uint256 depositAmount = 1_000_000;
        uint256 mockRouterOutput = depositAmount; // 1:1 swap for simplicity
        router.setOutputAmount(mockRouterOutput);

        // Approve tokens for the mock router
        tokenIn.approve(address(router), depositAmount);

        // Create mock parameters for the swap
        Types.LiquidityRoute memory route = Types.LiquidityRoute({
            router: address(router),
            routeData: abi.encodeWithSignature(
                "swap(address,address,uint256)",
                address(tokenIn),
                address(mockToken),
                depositAmount
            )
        });

        // Create minimal SignedIntent with only required fields for the test
        Types.IntentInfo memory intentInfo = Types.IntentInfo({
            intentReactor: address(riftReactorEnhanced),
            nonce: 0,
            tokenIn: address(tokenIn),
            auction: Types.DutchAuctionInfo({startBlock: 0, endBlock: 0, minSats: 0, maxSats: 0}),
            depositLiquidityParams: Types.ReactorDepositLiquidityParams({
                depositAmount: depositAmount,
                depositSalt: bytes32(0),
                depositOwnerAddress: address(0),
                btcPayoutScriptPubKey: bytes25(0),
                confirmationBlocks: 0,
                safeBlockLeaf: Types.BlockLeaf({blockHash: bytes32(0), height: 0, cumulativeChainwork: 0}),
                safeBlockSiblings: new bytes32[](0),
                safeBlockPeaks: new bytes32[](0)
            }),
            permit2TransferInfo: Types.Permit2TransferInfo({
                permitTransferFrom: ISignatureTransfer.PermitTransferFrom({
                    permitted: ISignatureTransfer.TokenPermissions({token: address(0), amount: 0}),
                    nonce: 0,
                    deadline: 0
                }),
                transferDetails: ISignatureTransfer.SignatureTransferDetails({to: address(0), requestedAmount: 0}),
                owner: address(0),
                signature: bytes("")
            })
        });

        Types.SignedIntent memory signedIntent = Types.SignedIntent({
            info: intentInfo,
            signature: bytes(""),
            orderHash: bytes32(0)
        });

        // Record balances before swap
        uint256 preCallBalance = mockToken.balanceOf(address(riftReactorEnhanced));

        // Execute the swap (should not revert)
        vm.prank(address(this));
        riftReactorEnhanced.executeSwap(route, signedIntent, depositAmount);

        // Verify the post-swap balance increased by the expected amount
        uint256 postCallBalance = mockToken.balanceOf(address(riftReactorEnhanced));
        assertEq(
            postCallBalance - preCallBalance,
            mockRouterOutput,
            "Router should have transferred the correct amount of tokens"
        );
    }

    /// @notice Test that _executeSwap reverts when the router call fails
    function testExecuteSwapRouterCallFailed() public {
        uint256 depositAmount = 1_000_000;

        // Set the router to fail
        router.setShouldFail(true);

        // Create route with failing flag
        Types.LiquidityRoute memory route = Types.LiquidityRoute({
            router: address(router),
            routeData: abi.encodeWithSignature(
                "swap(address,address,uint256)",
                address(tokenIn),
                address(mockToken),
                depositAmount
            )
        });

        // Create minimal SignedIntent
        Types.IntentInfo memory intentInfo = Types.IntentInfo({
            intentReactor: address(riftReactorEnhanced),
            nonce: 0,
            tokenIn: address(tokenIn),
            auction: Types.DutchAuctionInfo({startBlock: 0, endBlock: 0, minSats: 0, maxSats: 0}),
            depositLiquidityParams: Types.ReactorDepositLiquidityParams({
                depositAmount: depositAmount,
                depositSalt: bytes32(0),
                depositOwnerAddress: address(0),
                btcPayoutScriptPubKey: bytes25(0),
                confirmationBlocks: 0,
                safeBlockLeaf: Types.BlockLeaf({blockHash: bytes32(0), height: 0, cumulativeChainwork: 0}),
                safeBlockSiblings: new bytes32[](0),
                safeBlockPeaks: new bytes32[](0)
            }),
            permit2TransferInfo: Types.Permit2TransferInfo({
                permitTransferFrom: ISignatureTransfer.PermitTransferFrom({
                    permitted: ISignatureTransfer.TokenPermissions({token: address(0), amount: 0}),
                    nonce: 0,
                    deadline: 0
                }),
                transferDetails: ISignatureTransfer.SignatureTransferDetails({to: address(0), requestedAmount: 0}),
                owner: address(0),
                signature: bytes("")
            })
        });

        Types.SignedIntent memory signedIntent = Types.SignedIntent({
            info: intentInfo,
            signature: bytes(""),
            orderHash: bytes32(0)
        });

        // Expect revert with RouterCallFailed error
        vm.expectRevert(Errors.RouterCallFailed.selector);
        riftReactorEnhanced.executeSwap(route, signedIntent, depositAmount);
    }

    /// @notice Test that _executeSwap reverts when insufficient cbBTC is returned
    function testExecuteSwapInsufficientCbBTC() public {
        uint256 depositAmount = 1_000_000;

        // Set the router to return less than the required amount
        router.setOutputAmount(depositAmount - 1); // Return 1 less than required

        // Create route
        Types.LiquidityRoute memory route = Types.LiquidityRoute({
            router: address(router),
            routeData: abi.encodeWithSignature(
                "swap(address,address,uint256)",
                address(tokenIn),
                address(mockToken),
                depositAmount
            )
        });

        // Create minimal SignedIntent
        Types.IntentInfo memory intentInfo = Types.IntentInfo({
            intentReactor: address(riftReactorEnhanced),
            nonce: 0,
            tokenIn: address(tokenIn),
            auction: Types.DutchAuctionInfo({startBlock: 0, endBlock: 0, minSats: 0, maxSats: 0}),
            depositLiquidityParams: Types.ReactorDepositLiquidityParams({
                depositAmount: depositAmount,
                depositSalt: bytes32(0),
                depositOwnerAddress: address(0),
                btcPayoutScriptPubKey: bytes25(0),
                confirmationBlocks: 0,
                safeBlockLeaf: Types.BlockLeaf({blockHash: bytes32(0), height: 0, cumulativeChainwork: 0}),
                safeBlockSiblings: new bytes32[](0),
                safeBlockPeaks: new bytes32[](0)
            }),
            permit2TransferInfo: Types.Permit2TransferInfo({
                permitTransferFrom: ISignatureTransfer.PermitTransferFrom({
                    permitted: ISignatureTransfer.TokenPermissions({token: address(0), amount: 0}),
                    nonce: 0,
                    deadline: 0
                }),
                transferDetails: ISignatureTransfer.SignatureTransferDetails({to: address(0), requestedAmount: 0}),
                owner: address(0),
                signature: bytes("")
            })
        });

        Types.SignedIntent memory signedIntent = Types.SignedIntent({
            info: intentInfo,
            signature: bytes(""),
            orderHash: bytes32(0)
        });

        // Expect revert with InsufficientCbBTC error
        vm.expectRevert(Errors.InsufficientCbBTC.selector);
        riftReactorEnhanced.executeSwap(route, signedIntent, depositAmount);
    }
}

// Mock Router contract for testing swaps
contract MockRouter {
    address public immutable outputToken;
    uint256 public outputAmount;
    bool public shouldFail;

    constructor(address _outputToken) {
        outputToken = _outputToken;
    }

    function setOutputAmount(uint256 _amount) external {
        outputAmount = _amount;
    }

    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    function swap(address inputToken, address, uint256) external returns (bool) {
        if (shouldFail) {
            revert("Router call failed");
        }

        MockToken(outputToken).transfer(msg.sender, outputAmount);
        return true;
    }
}
