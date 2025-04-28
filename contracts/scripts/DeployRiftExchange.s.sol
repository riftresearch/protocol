// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

import "forge-std/src/Script.sol";
import "forge-std/src/console.sol";
import "../src/RiftExchange.sol";
import {HelperTypes} from "../tests/utils/HelperTypes.sol";

contract DeployRiftExchange is Script {
    function stringToUint(string memory s) internal pure returns (uint256) {
        bytes memory b = bytes(s);
        uint256 result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            uint256 c = uint256(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
        return result;
    }

    function _substring(string memory _base, int256 _length, int256 _offset) internal pure returns (string memory) {
        bytes memory _baseBytes = bytes(_base);

        assert(uint256(_offset + _length) <= _baseBytes.length);

        string memory _tmp = new string(uint256(_length));
        bytes memory _tmpBytes = bytes(_tmp);

        uint256 j = 0;
        for (uint256 i = uint256(_offset); i < uint256(_offset + _length); i++) {
            _tmpBytes[j++] = _baseBytes[i];
        }

        return string(_tmpBytes);
    }

    function getDeploymentParams(
        string memory checkpointFile
    ) public returns (HelperTypes.DeploymentParams memory deploymentParams) {
        // Prepare the curl command with jq
        string[] memory curlInputs = new string[](3);
        curlInputs[0] = "bash";
        curlInputs[1] = "-c";
        curlInputs[2] = string.concat(
            "../target/release/test-utils get-deployment-params --checkpoint-file ",
            checkpointFile
        );
        deploymentParams = abi.decode(vm.ffi(curlInputs), (HelperTypes.DeploymentParams));
    }

    struct ChainSpecificAddresses {
        address verifierContractAddress;
        address depositTokenAddress;
        address feeRouterAddress;
    }

    function selectAddressesByChainId() public view returns (ChainSpecificAddresses memory) {
        // Base Mainnet (mocked verifier)
        if (block.chainid == 8453) {
            return
                ChainSpecificAddresses(
                    address(0x2e4936506870679e8Fdc433a5959445b2aa01f04),
                    address(0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf),
                    address(0xfEe8d79961c529E06233fbF64F96454c2656BFEE)
                );
        }
        revert("Unsupported chain");
    }

    function run() external {
        vm.startBroadcast();
        // TODO: add deployment logic here
        /*
        uint16 takerFeeBips = 20;

        console.log("Deploying RiftExchange on chain with ID:", block.chainid);

        ChainSpecificAddresses memory chainSpecificAddresses = selectAddressesByChainId();

        console.log("Building deployment params...");
        HelperTypes.DeploymentParams memory deploymentParams = getDeploymentParams("../bitcoin_checkpoint_885041.zst");
        console.log("Deployment params built...");

        RiftExchange riftExchange = new RiftExchange({
            _mmrRoot: deploymentParams.mmrRoot,
            _depositToken: chainSpecificAddresses.depositTokenAddress,
            _circuitVerificationKey: deploymentParams.circuitVerificationKey,
            _verifier: chainSpecificAddresses.verifierContractAddress,
            _feeRouter: chainSpecificAddresses.feeRouterAddress,
            _takerFeeBips: takerFeeBips,
            _tipBlockLeaf: deploymentParams.tipBlockLeaf
        });
        

        console.log("RiftExchange deployed at address:", address(riftExchange));
        */

        vm.stopBroadcast();
    }
}
