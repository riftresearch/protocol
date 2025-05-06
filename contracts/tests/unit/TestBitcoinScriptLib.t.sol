// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.27;

import {Test} from "forge-std/src/Test.sol";
import {Vm} from "forge-std/src/Vm.sol";
import {RiftTest} from "../utils/RiftTest.t.sol";
import {BitcoinScriptLib} from "../../src/libraries/BitcoinScriptLib.sol";

contract BitcoinScriptLibUnitTest is RiftTest {
    /// forge-config: default.isolate = true
    function test_validateScriptPubKey_p2pkh() public {
        // p2pkh
        bytes memory p2pkh = hex"76a914fd5ec8ae0fd939ac925a8eccdc990fbbae9badcc88ac";

        bool valid;
        vm.startSnapshotGas("BitcoinScriptLibTest", "p2pkh_validate");
        valid = BitcoinScriptLib.validateScriptPubKey(p2pkh);
        vm.stopSnapshotGas("BitcoinScriptLibTest", "p2pkh_validate");
        assertEq(valid, true, "validateScriptPubKey failed, p2pkh");
    }

    /// forge-config: default.isolate = true
    function test_validateScriptPubKey_p2sh() public {
        // p2sh
        bytes memory p2sh = hex"a9145d16d60c9bb88d9e7c8ee042c676ac978ceea77487";

        bool valid;
        vm.startSnapshotGas("BitcoinScriptLibTest", "p2sh_validate");
        valid = BitcoinScriptLib.validateScriptPubKey(p2sh);
        vm.stopSnapshotGas("BitcoinScriptLibTest", "p2sh_validate");
        assertEq(valid, true, "validateScriptPubKey failed, p2sh");
    }

    /// forge-config: default.isolate = true
    function test_validateScriptPubKey_p2wpkh() public {
        // p2wpkh
        bytes memory p2wpkh = hex"00148bd9d208f3980a310156dc7a87883fead70d32e0";

        bool valid;
        vm.startSnapshotGas("BitcoinScriptLibTest", "p2wpkh_validate");
        valid = BitcoinScriptLib.validateScriptPubKey(p2wpkh);
        vm.stopSnapshotGas("BitcoinScriptLibTest", "p2wpkh_validate");
        assertEq(valid, true, "validateScriptPubKey failed, p2wpkh");
    }

    /// forge-config: default.isolate = true
    function test_validateScriptPubKey_p2wsh() public {
        // p2wsh
        bytes memory p2wsh = hex"002065f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3";

        bool valid;
        vm.startSnapshotGas("BitcoinScriptLibTest", "p2wsh_validate");
        valid = BitcoinScriptLib.validateScriptPubKey(p2wsh);
        vm.stopSnapshotGas("BitcoinScriptLibTest", "p2wsh_validate");
        assertEq(valid, true, "validateScriptPubKey failed, p2wsh");
    }

    /// forge-config: default.isolate = true
    function test_validateScriptPubKey_p2tr() public {
        // p2tr
        bytes memory p2tr = hex"51200f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667";

        bool valid;
        vm.startSnapshotGas("BitcoinScriptLibTest", "p2tr_validate");
        valid = BitcoinScriptLib.validateScriptPubKey(p2tr);
        vm.stopSnapshotGas("BitcoinScriptLibTest", "p2tr_validate");
        assertEq(valid, true, "validateScriptPubKey failed, p2tr");
    }
}
