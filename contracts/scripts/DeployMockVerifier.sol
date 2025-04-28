// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

import "forge-std/src/Script.sol";
import "forge-std/src/console.sol";
import "sp1-contracts/contracts/src/SP1MockVerifier.sol";

contract DeployMockVerifier is Script {
    function run() external {
        vm.startBroadcast();

        console.log("Deploying SP1MockVerifier on chain with ID:", block.chainid);

        SP1MockVerifier mockVerifier = new SP1MockVerifier();

        console.log("SP1MockVerifier deployed at:", address(mockVerifier));

        vm.stopBroadcast();
    }
}
