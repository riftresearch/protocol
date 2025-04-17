// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/src/Test.sol";
import {RiftTest} from "../utils/RiftTest.sol";
import {BitcoinScriptLib} from "../../src/libraries/BitcoinScriptLib.sol";

contract BitcoinScriptLibUnitTest is RiftTest {
    function test_validateScriptPubKey() public pure {
        // p2pkh
        bytes25 p2pkh = bytes25(hex"76a914fd5ec8ae0fd939ac925a8eccdc990fbbae9badcc88ac");
        // p2sh
        bytes25 p2sh = bytes25(hex"a9145d16d60c9bb88d9e7c8ee042c676ac978ceea77487");
        // p2wpkh
        bytes25 p2wpkh = bytes25(hex"00148bd9d208f3980a310156dc7a87883fead70d32e0");

        bool valid = BitcoinScriptLib.validateScriptPubKey(p2pkh);
        assertEq(valid, true, "validateScriptPubKey failed, p2pkh");

        valid = BitcoinScriptLib.validateScriptPubKey(p2sh);
        assertEq(valid, true, "validateScriptPubKey failed, p2sh");

        valid = BitcoinScriptLib.validateScriptPubKey(p2wpkh);
        assertEq(valid, true, "validateScriptPubKey failed, p2wpkh");
    }
}
