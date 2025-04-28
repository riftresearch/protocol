// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.27;

import "../../src/interfaces/IRiftExchange.sol";
import {HelperTypes} from "../utils/HelperTypes.sol";
import {BitcoinLightClient} from "../../src/BitcoinLightClient.sol";
import {BitcoinScriptLib} from "../../src/libraries/BitcoinScriptLib.sol";
import {HashLib} from "../../src/libraries/HashLib.sol";
import {PeriodLib} from "../../src/libraries/PeriodLib.sol";
import {RiftExchange} from "../../src/RiftExchange.sol";
import {RiftTest} from "../utils/RiftTest.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";
import {FeeLib} from "../../src/libraries/FeeLib.sol";
import {OrderValidationLib} from "../../src/libraries/OrderValidationLib.sol";

import "forge-std/src/console.sol";

contract RiftExchangeUnitTest is RiftTest {
    using HashLib for Order;
    using HashLib for Payment;
    using HashLib for BlockLeaf;

    // hacky way to get nice formatting for the vault in logs
    event OrderLog(Order order);
    event OrderCommitmentLog(bytes32 orderCommitment);
    event LogOrders(Order[] orders);
    uint256 constant MAX_ORDERS = 2;

    // functional clone of validateOrderHashes, but doesn't attempt to validate the orders existence in storage
    // used to generate test data for circuits
    // TODO: directly call the rust api from here as part of fuzzer
    function generateOrderHash(Order[] memory orders) internal pure returns (bytes32) {
        bytes32[] memory orderHashes = new bytes32[](orders.length);
        for (uint256 i = 0; i < orders.length; i++) {
            orderHashes[i] = orders[i].hash();
        }
        return EfficientHashLib.hash(orderHashes);
    }

    // use to generate test data for circuits
    // TODO: directly call the rust api from here as part of fuzzer
    function test_orderHashes(Order memory order, uint256) public {
        // uint64 max here so it can be set easily in rust
        bound(order.index, 0, uint256(type(uint64).max));
        bytes32 order_commitment = order.hash();
        emit OrderLog(order);
        emit OrderCommitmentLog(order_commitment);
    }

    // used to generate test data for circuits
    // TODO: directly call the rust api from here as part of fuzzer
    function test_blockLeafHasher() public pure {
        BlockLeaf memory blockLeaf = BlockLeaf({
            blockHash: hex"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            height: 0,
            cumulativeChainwork: 4295032833
        });

        console.log("blockLeaf fields");
        console.logBytes32(blockLeaf.blockHash);
        console.logBytes32(bytes32(uint256(blockLeaf.height)));
        console.logBytes32(bytes32(blockLeaf.cumulativeChainwork));

        bytes32 blockLeafHash = blockLeaf.hash();
        console.log("blockLeafHash");
        console.logBytes32(blockLeafHash);
    }

    function constrainOrder(Order memory order, uint64 maxValue) internal pure returns (Order memory) {
        return
            Order({
                index: order.index % maxValue,
                timestamp: order.timestamp % maxValue,
                unlockTimestamp: order.unlockTimestamp % maxValue,
                amount: order.amount % maxValue,
                takerFee: order.takerFee % maxValue,
                expectedSats: order.expectedSats % maxValue,
                bitcoinScriptPubKey: order.bitcoinScriptPubKey,
                designatedReceiver: order.designatedReceiver,
                owner: order.owner,
                salt: order.salt,
                confirmationBlocks: order.confirmationBlocks,
                safeBitcoinBlockHeight: order.safeBitcoinBlockHeight
            });
    }

    // use to generate test data for circuits
    function test_aggregateOrderHashes(Order[1] memory singleOrderSet, Order[2] memory twoOrderSet, uint256) public {
        uint64 maxValue = type(uint64).max;

        Order[] memory singleOrderSetArray = new Order[](1);
        singleOrderSetArray[0] = constrainOrder(singleOrderSet[0], maxValue);
        bytes32 singleOrderCommitment = generateOrderHash(singleOrderSetArray);
        emit LogOrders(singleOrderSetArray);
        emit OrderCommitmentLog(singleOrderCommitment);

        Order[] memory twoOrderSetArray = new Order[](2);
        twoOrderSetArray[0] = constrainOrder(twoOrderSet[0], maxValue);
        twoOrderSetArray[1] = constrainOrder(twoOrderSet[1], maxValue);
        bytes32 twoOrderCommitment = generateOrderHash(twoOrderSetArray);
        emit LogOrders(twoOrderSetArray);
        emit OrderCommitmentLog(twoOrderCommitment);
    }

    // Test that depositLiquidity appends a new commitment to the vaultHashes array
    function testFuzz_createOrder(
        uint256 depositAmount,
        uint64 expectedSats,
        uint8 confirmationBlocks,
        uint256
    ) public {
        // [0] bound deposit amount & expected sats
        depositAmount = bound(
            depositAmount,
            FeeLib.calculateMinDepositAmount(exchange.takerFeeBips()),
            type(uint64).max
        );
        expectedSats = uint64(bound(expectedSats, OrderValidationLib.MIN_OUTPUT_SATS, type(uint64).max));
        confirmationBlocks = uint8(
            bound(confirmationBlocks, OrderValidationLib.MIN_CONFIRMATION_BLOCKS, type(uint8).max)
        );
        _createOrderWithAssertions(depositAmount, expectedSats, confirmationBlocks);
    }

    function testFuzz_refundOrder(
        uint256 depositAmount,
        uint64 expectedSats,
        uint8 confirmationBlocks,
        uint256
    ) public {
        // [0] bound inputs
        depositAmount = bound(
            depositAmount,
            FeeLib.calculateMinDepositAmount(exchange.takerFeeBips()),
            type(uint64).max
        );
        expectedSats = uint64(bound(expectedSats, OrderValidationLib.MIN_OUTPUT_SATS, type(uint64).max));
        confirmationBlocks = uint8(
            bound(confirmationBlocks, OrderValidationLib.MIN_CONFIRMATION_BLOCKS, type(uint8).max)
        );

        // [1] create initial deposit and get vault
        Order memory order = _createOrderWithAssertions(depositAmount, expectedSats, confirmationBlocks);
        uint256 initialBalance = syntheticBTC.balanceOf(address(this));

        // [2] warp to future time after lockup period
        vm.warp(block.timestamp + PeriodLib.calculateDepositLockupPeriod(confirmationBlocks) + 1);

        // [3] withdraw and capture updated vault from logs
        vm.recordLogs();
        exchange.refundOrder(order);
        Order memory updatedOrder = _extractSingleOrderFromLogs(vm.getRecordedLogs());

        // [4] verify updated vault commitment matches stored commitment
        bytes32 storedCommitment = exchange.orderHashes(order.index);
        bytes32 calculatedCommitment = updatedOrder.hash();
        assertEq(calculatedCommitment, storedCommitment, "Order commitment mismatch");

        // [5] verify vault is now empty
        assertEq(updatedOrder.amount, 0, "Updated order should be empty");
        assertEq(updatedOrder.index, order.index, "Order index should remain unchanged");

        // [6] verify tokens were transferred correctly
        assertEq(syntheticBTC.balanceOf(address(this)), initialBalance + depositAmount, "Incorrect withdrawal amount");
    }

    function testFuzz_submitPaymentProofs(SubmitPaymentProofParams memory params, uint256) public {
        // [0] bound inputs
        params.order.amount = bound(
            params.order.amount,
            FeeLib.calculateMinDepositAmount(exchange.takerFeeBips()),
            type(uint64).max
        );
        params.order.expectedSats = uint64(
            bound(params.order.expectedSats, OrderValidationLib.MIN_OUTPUT_SATS, type(uint64).max)
        );
        params.order.confirmationBlocks = uint8(
            bound(params.order.confirmationBlocks, OrderValidationLib.MIN_CONFIRMATION_BLOCKS, type(uint8).max)
        );

        // [1] create deposit vault
        Order memory order = _createOrderWithAssertions(
            params.order.amount,
            params.order.expectedSats,
            params.order.confirmationBlocks
        );

        // [3] create dummy proof data
        (bytes memory proof, bytes memory compressedBlockLeaves) = _getMockProof();

        // [4] create dummy tip block data
        bytes32 priorMmrRoot = exchange.mmrRoot();

        (
            HelperTypes.MMRProof memory mmrProof,
            HelperTypes.MMRProof memory tipMmrProof
        ) = _generateFakeBlockWithConfirmationsMMRProofFFI(0, params.order.confirmationBlocks);
        /*
            SubmitSwapProofParams[] calldata swapParams,
            BlockProofParams calldata blockProofParams,
            bytes calldata proof
        */

        // [4] submit swap proof and capture logs
        vm.recordLogs();
        SubmitPaymentProofParams[] memory paymentParams = new SubmitPaymentProofParams[](1);

        paymentParams[0] = SubmitPaymentProofParams({
            paymentBitcoinTxid: params.paymentBitcoinTxid,
            order: order,
            paymentBitcoinBlockLeaf: mmrProof.blockLeaf,
            paymentBitcoinBlockSiblings: mmrProof.siblings,
            paymentBitcoinBlockPeaks: mmrProof.peaks
        });

        BlockProofParams memory blockProofParams = BlockProofParams({
            priorMmrRoot: priorMmrRoot,
            newMmrRoot: mmrProof.mmrRoot,
            compressedBlockLeaves: compressedBlockLeaves,
            tipBlockLeaf: tipMmrProof.blockLeaf
        });
        console.log("blockProofParams.tipBlockLeaf.height", blockProofParams.tipBlockLeaf.height);

        exchange.submitPaymentProofs(paymentParams, blockProofParams, proof);

        // [5] extract payment from logs
        Payment memory createdPayment = _extractSinglePaymentFromLogs(vm.getRecordedLogs());
        uint256 paymentIndex = exchange.getTotalPayments() - 1;
        bytes32 hash = exchange.paymentHashes(paymentIndex);

        // [6] verify payment details
        assertEq(createdPayment.index, paymentIndex, "Payment index should match");
        assertEq(order.designatedReceiver, address(this), "Payout address should match");
        assertEq(uint8(createdPayment.state), uint8(PaymentState.Proved), "Payment should be in Proved state");

        // [7] verify hash
        bytes32 offchainHash = createdPayment.hash();
        assertEq(offchainHash, hash, "Offchain payment hash should match");
    }

    struct FuzzReleaseLiquidityParams {
        bytes32 paymentBitcoinTxid;
        uint256 depositAmount;
        uint64 expectedSats;
        uint8 confirmationBlocks;
    }

    // Helper function to set up vaults and submit swap proof
    function _setupVaultsAndSubmitSwap(
        FuzzReleaseLiquidityParams memory params
    )
        internal
        returns (
            Order memory order,
            Payment memory createdPayment,
            HelperTypes.MMRProof memory paymentMmrProof,
            HelperTypes.MMRProof memory tipMmrProof
        )
    {
        // Create deposit vault
        order = _createOrderWithAssertions(params.depositAmount, params.expectedSats, params.confirmationBlocks);

        // [3] create dummy proof data
        (bytes memory proof, bytes memory compressedBlockLeaves) = _getMockProof();

        bytes32 priorMmrRoot = exchange.mmrRoot();
        (paymentMmrProof, tipMmrProof) = _generateFakeBlockWithConfirmationsMMRProofFFI(1, params.confirmationBlocks);

        assertEq(paymentMmrProof.mmrRoot, tipMmrProof.mmrRoot, "Mmr roots should match");

        vm.recordLogs();
        SubmitPaymentProofParams[] memory paymentParams = new SubmitPaymentProofParams[](1);
        paymentParams[0] = SubmitPaymentProofParams({
            paymentBitcoinTxid: params.paymentBitcoinTxid,
            order: order,
            paymentBitcoinBlockLeaf: paymentMmrProof.blockLeaf,
            paymentBitcoinBlockSiblings: paymentMmrProof.siblings,
            paymentBitcoinBlockPeaks: paymentMmrProof.peaks
        });
        BlockProofParams memory blockProofParams = BlockProofParams({
            priorMmrRoot: priorMmrRoot,
            newMmrRoot: tipMmrProof.mmrRoot,
            compressedBlockLeaves: compressedBlockLeaves,
            tipBlockLeaf: tipMmrProof.blockLeaf
        });

        exchange.submitPaymentProofs(paymentParams, blockProofParams, proof);

        createdPayment = _extractSinglePaymentFromLogs(vm.getRecordedLogs());
        return (order, createdPayment, paymentMmrProof, tipMmrProof);
    }

    // Helper function to verify balances and empty vaults
    function _verifyBalancesAndVaults(
        Order memory order,
        uint256 initialBalance,
        uint256 initialFeeBalance,
        uint256 totalSwapOutput,
        uint256 totalSwapFee
    ) internal view {
        // Verify funds were transferred correctly
        assertEq(
            syntheticBTC.balanceOf(address(this)),
            initialBalance + totalSwapOutput,
            "Incorrect amount transferred to recipient"
        );

        assertEq(exchange.accumulatedFees(), initialFeeBalance + totalSwapFee, "Incorrect fee amount accumulated");

        // Verify vaults were emptied
        bytes32 orderCommitment = exchange.orderHashes(order.index);
        order.amount = 0;
        order.takerFee = 0;
        bytes32 expectedCommitment = order.hash();
        assertEq(orderCommitment, expectedCommitment, "Order should be empty");
    }

    function testFuzz_releaseLiquidity(FuzzReleaseLiquidityParams memory params, uint256) public {
        // Bound inputs
        params.depositAmount = bound(
            params.depositAmount,
            FeeLib.calculateMinDepositAmount(exchange.takerFeeBips()),
            type(uint64).max
        );
        params.expectedSats = uint64(bound(params.expectedSats, OrderValidationLib.MIN_OUTPUT_SATS, type(uint64).max));
        params.confirmationBlocks = uint8(
            bound(params.confirmationBlocks, OrderValidationLib.MIN_CONFIRMATION_BLOCKS, type(uint8).max)
        );

        console.log("[0] setup vaults and submit swap");

        // Set up vaults and submit swap
        (
            Order memory order,
            Payment memory createdPayment,
            HelperTypes.MMRProof memory paymentMmrProof,
            HelperTypes.MMRProof memory tipMmrProof
        ) = _setupVaultsAndSubmitSwap(params);

        // Record initial balances
        uint256 initialBalance = syntheticBTC.balanceOf(address(this));
        uint256 initialFeeBalance = exchange.accumulatedFees();

        // validate the erc20 balance of the contract is equal to the amount sent params.depositAmount
        assertEq(
            syntheticBTC.balanceOf(address(exchange)),
            params.depositAmount,
            "Contract should have the correct balance"
        );

        // Warp past challenge period
        vm.warp(block.timestamp + PeriodLib.calculateChallengePeriod(params.confirmationBlocks) + 2);

        // Release liquidity
        console.log("[1] release liquidity");
        vm.recordLogs();

        SettleOrderParams memory settleOrderParams = SettleOrderParams({
            order: order,
            payment: createdPayment,
            paymentBitcoinBlockSiblings: paymentMmrProof.siblings,
            paymentBitcoinBlockPeaks: paymentMmrProof.peaks,
            tipBlockHeight: tipMmrProof.blockLeaf.height
        });

        SettleOrderParams[] memory settleOrderParamsArray = new SettleOrderParams[](1);
        settleOrderParamsArray[0] = settleOrderParams;

        exchange.settleOrders(settleOrderParamsArray);

        // Verify swap completion
        Payment memory updatedPayment = _extractSinglePaymentFromLogs(vm.getRecordedLogs());
        assertEq(uint8(updatedPayment.state), uint8(PaymentState.Settled), "Payment should be finalized");

        // Verify balances and vaults
        _verifyBalancesAndVaults(order, initialBalance, initialFeeBalance, order.amount, order.takerFee);

        // Verify fee router balance and payout
        uint256 accountedFeeRouterBalancePrePayout = exchange.accumulatedFees();
        uint256 feeRouterBalancePrePayout = syntheticBTC.balanceOf(address(exchange));

        console.log("accountedFeeRouterBalancePrePayout", accountedFeeRouterBalancePrePayout);
        console.log("feeRouterBalancePrePayout", feeRouterBalancePrePayout);

        assertEq(
            accountedFeeRouterBalancePrePayout,
            feeRouterBalancePrePayout - initialFeeBalance,
            "accounted fee balance should match the actual contract balance of USDC"
        );

        exchange.withdrawFees();
        assertEq(
            syntheticBTC.balanceOf(exchange.feeRouter()),
            feeRouterBalancePrePayout,
            "Fee router should have received all fees"
        );
    }
}
