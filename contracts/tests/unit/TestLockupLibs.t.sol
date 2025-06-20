// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.28;

import "forge-std/src/Test.sol";
import "forge-std/src/console.sol";

import {OrderLockupLib}     from "../../src/libraries/OrderLockupLib.sol";
import {ChallengePeriodLib} from "../../src/libraries/ChallengePeriodLib.sol";

contract TestLockupLibs is Test {

    function testPrint_t_k_challengePeriodLib() public pure {
        console.log("*** tau_challenge(k), finalityTime = 12s ***");
        uint64 finalityTime = 12;                       // seconds
        for (uint16 k = 1; k <= 2016; ++k) {
            uint16 delta = uint16(k);
            uint64 seconds_ = ChallengePeriodLib.calculateChallengePeriod(delta, finalityTime);
            console.log(string.concat("delta_blocks =", vm.toString(delta), "=>", vm.toString(seconds_), "s"));
        }
    }

    function testPrint_lockup_orderLockupLib() public pure {
        console.log("*** T_lock_up with blockFinalityTime = 12s ***");
        uint64 finalityTime = 12;                       // seconds

        for (uint16 k = 1; k <= 255; ++k) {
            uint8 confirmations = uint8(k);
            uint64 lockup = OrderLockupLib.calculateLockupPeriod(
                confirmations,
                finalityTime
            );
            console.log(string.concat("k =", vm.toString(k), "=>", vm.toString(lockup), "s"));
        }
    }
}
