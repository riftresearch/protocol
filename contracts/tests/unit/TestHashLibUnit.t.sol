// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.27;

import {Test} from "forge-std/src/Test.sol";
import {RiftTest} from "../utils/RiftTest.t.sol";

import {HashLib} from "../../src/libraries/HashLib.sol";
import {BlockLeaf} from "../../src/interfaces/IBitcoinLightClient.sol";
import {HelperTypes} from "../utils/HelperTypes.t.sol";
import {Order, Payment, OrderState, PaymentState} from "../../src/interfaces/IRiftExchange.sol";

contract HashLibUnitTest is RiftTest {
    using HashLib for BlockLeaf;
    using HashLib for Order;
    using HashLib for Payment;

    function setUp() public override {
        super.setUp();
    }

    /// forge-config: default.isolate = true
    function test_hashBlockLeaf() public {
        BlockLeaf memory leaf = BlockLeaf({
            blockHash: keccak256(abi.encodePacked(hex"dead")),
            height: 8000000,
            cumulativeChainwork: 1000000000000000000
        });
        vm.startSnapshotGas("HashLibUnitTest", "blockLeaf");
        leaf.hash();
        vm.stopSnapshotGas("HashLibUnitTest", "blockLeaf");
    }

    /// forge-config: default.isolate = true
    function test_hashOrder() public {
        Order memory order = Order({
            index: 1,
            timestamp: 1746663852,
            unlockTimestamp: 1746663852,
            amount: 100000000000000214120,
            takerFee: 10000000,
            expectedSats: 15642362353434,
            bitcoinScriptPubKey: hex"deaddeadedaedaeadeaddeadeadead",
            designatedReceiver: address(0xdeaddeadedaedaeadeaddeadeadead),
            owner: address(0xdeaddeadedaedaeadeaddeadeadead),
            salt: keccak256(abi.encodePacked(hex"dead")),
            confirmationBlocks: 64,
            safeBitcoinBlockHeight: 8000000,
            state: OrderState.Created
        });

        vm.startSnapshotGas("HashLibUnitTest", "order");
        order.hash();
        vm.stopSnapshotGas("HashLibUnitTest", "order");
    }

    /// forge-config: default.isolate = true
    function test_hashPayment() public {
        Payment memory payment = Payment({
            index: 1,
            orderIndex: 1,
            orderHash: keccak256(abi.encodePacked(hex"dead")),
            paymentBitcoinBlockLeaf: BlockLeaf({
                blockHash: keccak256(abi.encodePacked(hex"dead")),
                height: 8000000,
                cumulativeChainwork: 1000000000000000000
            }),
            challengeExpiryTimestamp: 1746663852,
            state: PaymentState.Proved
        });
        vm.startSnapshotGas("HashLibUnitTest", "payment");
        payment.hash();
        vm.stopSnapshotGas("HashLibUnitTest", "payment");
    }
}
