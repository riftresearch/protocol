// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/*───────────────────────────────────────────────────────────────────────────*
│                                 Imports                                    │
*────────────────────────────────────────────────────────────────────────────*/
import {RiftAuctionAdaptor} from "../../src/RiftAuctionAdaptor.sol";
import {BTCDutchAuctionHouse} from "../../src/BTCDutchAuctionHouse.sol";
import {IRiftAuctionAdaptor} from "../../src/interfaces/IRiftAuctionAdaptor.sol";
import {IBTCDutchAuctionHouse} from "../../src/interfaces/IBTCDutchAuctionHouse.sol";

import {FeeLib} from "../../src/libraries/FeeLib.sol";
import {HashLib} from "../../src/libraries/HashLib.sol";
import {DutchAuction} from "../../src/interfaces/IBTCDutchAuctionHouse.sol";
import {BaseDepositLiquidityParams} from "../../src/interfaces/IRiftExchange.sol";
import "../utils/HelperTypes.sol";

import {RiftTest} from "../utils/RiftTest.sol";
import {Vm} from "forge-std/src/Vm.sol";

/*───────────────────────────────────────────────────────────────────────────*
│                       RiftAuctionAdaptor ‑ Unit Tests                      │
*────────────────────────────────────────────────────────────────────────────*/
contract RiftAuctionAdaptorUnitTest is RiftTest {
    using HashLib for DutchAuction;

    /*───────────────────────────────────────────────────────────────────────*/
    /*                               Constants                               */
    /*───────────────────────────────────────────────────────────────────────*/
    address internal constant BUNDLER3       = 0x6BFd8137e702540E7A42B74178A4a49Ba43920C4;
    uint64  internal constant DECAY_BLOCKS   = 100;    // Arbitrary non‑zero value
    uint64  internal constant DEADLINE_DELAY = 7 days; // Auction deadline offset

    /*───────────────────────────────────────────────────────────────────────*/
    /*                               State                                   */
    /*───────────────────────────────────────────────────────────────────────*/
    BTCDutchAuctionHouse      internal auctionHouse;
    RiftAuctionAdaptor        internal adaptor;

    /*───────────────────────────────────────────────────────────────────────*/
    /*                               Helpers                                 */
    /*───────────────────────────────────────────────────────────────────────*/
    function _extractSingleAuctionFromLogs(Vm.Log[] memory logs) internal pure returns (DutchAuction memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IBTCDutchAuctionHouse.AuctionUpdated.selector) {
                return abi.decode(logs[i].data, (DutchAuction));
            }
        }
        revert("Auction not found");
    }

    /*───────────────────────────────────────────────────────────────────────*/
    /*                                Setup                                  */
    /*───────────────────────────────────────────────────────────────────────*/
    function setUp() public virtual override {
        super.setUp(); // Deploy syntheticBTC, verifier & helpers from RiftTest

        // Create a fresh light‑client checkpoint for the AuctionHouse instance
        HelperTypes.MMRProof memory initProof = _generateFakeBlockMMRProofFFI(0);

        auctionHouse = new BTCDutchAuctionHouse({
            _mmrRoot:               initProof.mmrRoot,
            _depositToken:          address(syntheticBTC),
            _circuitVerificationKey: bytes32("cvk"),
            _verifier:              address(verifier),
            _feeRouter:             address(0xfee),
            _takerFeeBips:          5,
            _tipBlockLeaf:          initProof.blockLeaf
        });

        adaptor = new RiftAuctionAdaptor({
            _bundler3:        BUNDLER3,
            _btcAuctionHouse: address(auctionHouse)
        });
    }

    /*───────────────────────────────────────────────────────────────────────*/
    /*                              Test: Access                             */
    /*───────────────────────────────────────────────────────────────────────*/
    /// @notice Non‑bundler3 callers MUST be rejected.
    function test_onlyBundler3Reverts() public {
        // Arrange ‑ give adaptor some tokens so that revert (if any) is due to access control
        syntheticBTC.mint(address(adaptor), 1e10);

        BaseDepositLiquidityParams memory baseParams;
        vm.expectRevert();
        adaptor.createAuction(1e18, 5e17, 1, uint64(block.timestamp + DEADLINE_DELAY), address(0), baseParams);
    }

    /*───────────────────────────────────────────────────────────────────────*/
    /*                         Test: Happy‑path createAuction                */
    /*───────────────────────────────────────────────────────────────────────*/
    /// @notice End‑to‑end test that `createAuction`:
    ///         1. Transfers tokens from adaptor → auctionHouse
    ///         2. Emits `AuctionUpdated` with correct parameters
    ///         3. Stores the auction hash on‑chain
    function test_createAuction_happyPath() public {
        /* ‑‑ Arrange ‑‑ */
        uint256 minDeposit   = FeeLib.calculateMinDepositAmount(auctionHouse.takerFeeBips());
        uint256 deposit      = minDeposit * 100; // Arbitrary > min
        uint256 startRateWad = 12e17;            // 1.2 sBTC / BTC (WAD)
        uint256 endRateWad   = 8e17;             // 0.8 sBTC / BTC (WAD)

        // Give the adaptor the sBTC it will auction
        syntheticBTC.mint(address(adaptor), deposit);

        HelperTypes.MMRProof memory safeProof = _generateFakeBlockMMRProofFFI(0);
        BaseDepositLiquidityParams memory baseParams = BaseDepositLiquidityParams({
            depositOwnerAddress:       address(this),
            btcPayoutScriptPubKey:     _generateBtcPayoutScriptPubKey(),
            depositSalt:               bytes32(uint256(keccak256("salt"))),
            confirmationBlocks:        auctionHouse.MIN_CONFIRMATION_BLOCKS(),
            safeBlockLeaf:             safeProof.blockLeaf
        });

        uint256 preAdaptorBal   = syntheticBTC.balanceOf(address(adaptor));
        uint256 preAuctionBal   = syntheticBTC.balanceOf(address(auctionHouse));
        uint256 startAmount     = (deposit * startRateWad) / 1e18;
        uint256 endAmount       = (deposit * endRateWad)   / 1e18;

        vm.recordLogs();
        /* ‑‑ Act ‑‑ */
        vm.prank(BUNDLER3);
        adaptor.createAuction(startRateWad, endRateWad, DECAY_BLOCKS, uint64(block.timestamp + DEADLINE_DELAY), address(0), baseParams);

        /* ‑‑ Assert ‑‑ */
        // [1] Token flow
        assertEq(syntheticBTC.balanceOf(address(adaptor)), 0, "Adaptor should have no tokens left");
        assertEq(
            syntheticBTC.balanceOf(address(auctionHouse)),
            preAuctionBal + deposit,
            "AuctionHouse token balance incorrect"
        );
        assertEq(preAdaptorBal - deposit, 0, "Accounting mismatch on adaptor balance");

        // [2] Auction event & storage
        DutchAuction memory auction = _extractSingleAuctionFromLogs(vm.getRecordedLogs());

        assertEq(auction.depositAmount, deposit, "Deposit amount mismatch");
        assertEq(auction.dutchAuctionParams.startBtcOut, startAmount, "startBtcOut mismatch");
        assertEq(auction.dutchAuctionParams.endBtcOut,   endAmount,   "endBtcOut mismatch");
        assertEq(auction.dutchAuctionParams.decayBlocks, DECAY_BLOCKS, "decayBlocks mismatch");

        bytes32 storedHash = auctionHouse.auctionHashes(auction.auctionIndex);
        assertEq(storedHash, auction.hash(), "Stored auction hash mismatch");
    }

    /*───────────────────────────────────────────────────────────────────────*/
    /*                  Test: Revert when startRate ≤ endRate               */
    /*───────────────────────────────────────────────────────────────────────*/
    function test_createAuction_revertsInvalidRates() public {
        uint256 deposit = FeeLib.calculateMinDepositAmount(auctionHouse.takerFeeBips()) * 10;
        syntheticBTC.mint(address(adaptor), deposit);

        BaseDepositLiquidityParams memory baseParams;
        vm.prank(BUNDLER3);
        vm.expectRevert(abi.encodeWithSelector(IBTCDutchAuctionHouse.InvalidStartBtcOut.selector));
        adaptor.createAuction(1e18, 2e18, DECAY_BLOCKS, uint64(block.timestamp + DEADLINE_DELAY), address(0), baseParams);
    }
}
