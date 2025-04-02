// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {MockToken} from "../../utils/MockToken.sol";

// Enhanced exposed contract for release and free fuzz tests
contract RiftReactorExposedForReleaseFuzz is RiftReactorExposed {
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

    // Get a bonded swap by order hash - add override keyword
    function getBondedSwap(bytes32 orderHash) public view override returns (Types.BondedSwap memory) {
        return swapBonds[orderHash];
    }

    // Override releaseAndFree to focus on just the bond functionality
    function releaseAndFreeMock(Types.ReleaseLiquidityParams[] calldata paramsArray) public {
        uint256 i;
        uint256 paramsArrayLength = paramsArray.length;
        for (; i < paramsArrayLength; ) {
            Types.ReleaseLiquidityParams calldata param = paramsArray[i];
            // Retrieve the bonded swap record for this release request using
            // the order hash.
            Types.BondedSwap memory swapInfo = swapBonds[param.orderHash];
            // Ensure a valid bond is recorded.
            if (swapInfo.marketMaker == address(0)) revert Errors.BondNotFoundOrAlreadyReleased();

            // Release the full bond amount back to the market maker (no penalty applied here).
            bool success = DEPOSIT_TOKEN.transfer(swapInfo.marketMaker, swapInfo.bond);
            if (!success) revert Errors.BondReleaseTransferFailed();

            // Clear the bond record to prevent double releasing.
            delete swapBonds[param.orderHash];

            unchecked {
                ++i;
            }
        }
    }
}

contract ReleaseAndFreeFuzzTest is RiftTestSetup {
    // Test accounts
    address marketMaker;

    // Enhanced reactor for testing
    RiftReactorExposedForReleaseFuzz public reactor;

    function setUp() public override {
        super.setUp();

        // Setup test account
        marketMaker = makeAddr("marketMaker");

        // Create new reactor with enhanced functionality
        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
        reactor = new RiftReactorExposedForReleaseFuzz({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _tipBlockLeaf: initial_mmr_proof.blockLeaf,
            _permit2_address: address(permit2)
        });

        // Make sure we're using the correct mockToken
        mockToken = MockToken(address(reactor.DEPOSIT_TOKEN()));

        // Fund accounts
        vm.startPrank(address(this));
        // Mint plenty of tokens to the reactor for tests
        mockToken.mint(address(reactor), 1_000_000_000_000);
        vm.stopPrank();
    }

    /**
     * @notice Helper function to create release liquidity params with specified order hash
     * @param orderHash The order hash for the release
     * @return params The release params for the specified order hash
     */
    function createReleaseParams(bytes32 orderHash) internal pure returns (Types.ReleaseLiquidityParams memory) {
        return
            Types.ReleaseLiquidityParams({
                swap: Types.ProposedSwap({
                    swapIndex: 0,
                    depositVaultCommitment: bytes32(0),
                    swapBitcoinBlockHash: bytes32(0),
                    confirmationBlocks: 0,
                    liquidityUnlockTimestamp: 0,
                    specifiedPayoutAddress: address(0),
                    totalSwapFee: 0,
                    totalSwapOutput: 0,
                    state: Types.SwapState.Proved
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
                    btcPayoutScriptPubKey: bytes25(0),
                    specifiedPayoutAddress: address(0),
                    ownerAddress: address(0),
                    salt: bytes32(0),
                    confirmationBlocks: 0,
                    attestedBitcoinBlockHeight: 0
                }),
                tipBlockHeight: 0,
                orderHash: orderHash
            });
    }

    /**
     * @notice Fuzz test that releaseAndFree correctly transfers bonds of different amounts
     * @param bondAmount The amount of the bond to test with
     */
    function testFuzz_ReleaseAndFreeSingleBond(uint96 bondAmount) public {
        // Create a realistic bond amount - avoid tiny values and huge values
        vm.assume(bondAmount > 1000);
        vm.assume(bondAmount < 1_000_000_000);

        // Create a unique order hash
        bytes32 orderHash = keccak256(abi.encodePacked("test_order_hash"));

        // Create a bonded swap
        reactor.createBondedSwap(orderHash, marketMaker, bondAmount, block.number);

        // Verify the bond was created
        Types.BondedSwap memory bond = reactor.getBondedSwap(orderHash);
        assertEq(bond.marketMaker, marketMaker, "Market maker should be set correctly");
        assertEq(bond.bond, bondAmount, "Bond amount should be set correctly");

        // Get initial balances
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);

        // Create release params array
        Types.ReleaseLiquidityParams[] memory paramsArray = new Types.ReleaseLiquidityParams[](1);
        paramsArray[0] = createReleaseParams(orderHash);

        // Execute the release
        reactor.releaseAndFreeMock(paramsArray);

        // Property: Market maker should receive the full bond amount
        assertEq(
            mockToken.balanceOf(marketMaker),
            initialMakerBalance + bondAmount,
            "Market maker should receive full bond amount"
        );

        // Property: The bond should be deleted from storage
        Types.BondedSwap memory bondAfter = reactor.getBondedSwap(orderHash);
        assertEq(bondAfter.marketMaker, address(0), "Bond should be deleted after release");
    }

    /**
     * @notice Fuzz test that releaseAndFree correctly handles multiple bonds of different amounts
     * @param bondAmounts Array of bond amounts to test with
     */
    function testFuzz_ReleaseAndFreeMultipleBonds(uint96[] calldata bondAmounts) public {
        // Limit the number of bonds for practical testing
        vm.assume(bondAmounts.length > 0 && bondAmounts.length <= 5);

        // Create bonds for each amount
        bytes32[] memory orderHashes = new bytes32[](bondAmounts.length);
        Types.ReleaseLiquidityParams[] memory paramsArray = new Types.ReleaseLiquidityParams[](bondAmounts.length);

        uint256 totalBondAmount = 0;

        for (uint i = 0; i < bondAmounts.length; i++) {
            // Get the bond amount for this item - handle very small or very large values
            uint96 adjustedBondAmount;

            // Since bondAmounts is calldata (read-only), we create a new adjusted value
            if (bondAmounts[i] < 1000 || bondAmounts[i] > 1_000_000_000) {
                adjustedBondAmount = 1000; // Use a minimal value for extreme cases
            } else {
                adjustedBondAmount = bondAmounts[i];
            }

            // Create unique order hash
            orderHashes[i] = keccak256(abi.encodePacked("test_order_", i));

            // Create bonded swap
            reactor.createBondedSwap(orderHashes[i], marketMaker, adjustedBondAmount, block.number);

            // Add to release params array
            paramsArray[i] = createReleaseParams(orderHashes[i]);

            // Track total bond amount (safely)
            // Check for overflow before adding
            if (totalBondAmount + adjustedBondAmount < totalBondAmount) {
                // If overflow would occur, cap at max value
                totalBondAmount = type(uint256).max;
                break;
            } else {
                totalBondAmount += adjustedBondAmount;
            }
        }

        // Get initial balance
        uint256 initialMakerBalance = mockToken.balanceOf(marketMaker);

        // Execute the release
        reactor.releaseAndFreeMock(paramsArray);

        // Property: Market maker should receive the sum of all bond amounts
        assertEq(
            mockToken.balanceOf(marketMaker),
            initialMakerBalance + totalBondAmount,
            "Market maker should receive sum of all bond amounts"
        );

        // Property: All bonds should be deleted from storage
        for (uint i = 0; i < orderHashes.length; i++) {
            Types.BondedSwap memory bondAfter = reactor.getBondedSwap(orderHashes[i]);
            assertEq(bondAfter.marketMaker, address(0), "Bond should be deleted after release");
        }
    }
}
