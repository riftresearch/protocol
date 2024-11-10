// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/RiftExchange.sol";
import {Upgrades} from "@openzeppelin-foundry-upgrades/Upgrades.sol";

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

    function fetchChainHeight() public returns (uint256) {
        // Prepare the curl command with jq
        string[] memory curlInputs = new string[](3);
        curlInputs[0] = "bash";
        curlInputs[1] = "-c";
        curlInputs[2] = string(
            abi.encodePacked(
                'curl --data-binary \'{"jsonrpc": "1.0", "id": "curltest", "method": "getblockchaininfo", "params": []}\' ',
                "-H 'content-type: text/plain;' -s ",
                vm.envString("BITCOIN_RPC"),
                " | jq -r '.result.blocks'"
            )
        );
        string memory _blockHeightStr = vm.toString(vm.ffi(curlInputs));
        string memory blockHeightStr = _substring(_blockHeightStr, int256(bytes(_blockHeightStr).length) - 2, 2);
        uint256 blockHeight = stringToUint(blockHeightStr);
        return blockHeight;
    }

    function fetchChainwork(bytes32 blockHash) public returns (uint256) {
        string memory blockHashStr = vm.toString(blockHash);
        // Prepare the curl command with jq
        string[] memory curlInputs = new string[](3);
        curlInputs[0] = "bash";
        curlInputs[1] = "-c";
        curlInputs[2] = string(
            abi.encodePacked(
                'curl --data-binary \'{"jsonrpc": "1.0", "id": "curltest", "method": "getblock", "params": ["',
                _substring(blockHashStr, int256(bytes(blockHashStr).length) - 2, 2),
                "\"]}' -H 'content-type: text/plain;' -s ",
                vm.envString("BITCOIN_RPC"),
                " | jq -r '.result.chainwork'"
            )
        );
        // Execute the curl command and get the result
        string memory chainWorkHex = vm.toString(vm.ffi(curlInputs));
        string memory blockHeightStr = _substring(chainWorkHex, int256(bytes(chainWorkHex).length) - 2, 2);
        uint256 chainwork = stringToUint(blockHeightStr);
        return chainwork;
    }

    function fetchBlockHash(uint256 height) public returns (bytes32) {
        string memory heightStr = vm.toString(height);
        string[] memory curlInputs = new string[](3);
        curlInputs[0] = "bash";
        curlInputs[1] = "-c";
        curlInputs[2] = string(
            abi.encodePacked(
                'curl --data-binary \'{"jsonrpc": "1.0", "id": "curltest", "method": "getblockhash", "params": [',
                heightStr,
                "]}' -H 'content-type: text/plain;' -s ",
                vm.envString("BITCOIN_RPC"),
                " | jq -r '.result'"
            )
        );
        bytes memory result = vm.ffi(curlInputs);
        return bytes32(result);
    }

    function calculateRetargetHeight(uint256 height) public pure returns (uint256) {
        uint256 retargetHeight = height - (height % 2016);
        return retargetHeight;
    }

    struct ChainSpecificAddresses {
        address verifierContractAddress;
        address depositTokenAddress;
    }

    function selectAddressesByChainId() public view returns (ChainSpecificAddresses memory) {
        // arbitrum sepolia
        if (block.chainid == 421614) {
            return
                ChainSpecificAddresses(
                    address(0x3B6041173B80E77f038f3F2C0f9744f04837185e),
                    address(0xC4af7CFe412805C4A751321B7b0799ca9b8dbE56)
                );
        }
        // holesky
        if (block.chainid == 17000) {
            return
                ChainSpecificAddresses(
                    address(0x3B6041173B80E77f038f3F2C0f9744f04837185e),
                    address(0x5150C7b0113650F9D17203290CEA88E52644a4a2)
                );
        }
        // arbitrum
        else if (block.chainid == 42161) {
            return
                ChainSpecificAddresses(
                    address(0x3B6041173B80E77f038f3F2C0f9744f04837185e),
                    address(0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9)
                );
        }
        revert("Unsupported chain");
    }

    function run() external {
        vm.startBroadcast();

        /*
        console.log("Deploying RiftExchange on chain with ID:", block.chainid);

        uint256 initialCheckpointHeight = fetchChainHeight() - 2;
        bytes32 initialBlockHash = fetchBlockHash(initialCheckpointHeight);
        bytes32 initialRetargetBlockHash = fetchBlockHash(calculateRetargetHeight(initialCheckpointHeight));
        uint256 initialChainwork = fetchChainwork(initialBlockHash);

        ChainSpecificAddresses memory addresses = selectAddressesByChainId();

        // Define the constructor arguments
        address verifierContractAddress = addresses.verifierContractAddress;
        address depositTokenAddress = addresses.depositTokenAddress;
        bytes32 verificationKeyHash = bytes32(0x00334569e4b8059d7b1a70c011d7d92b5d3ce28f2148b32cd2396aeda3ae5af1);
        address payable initialFeeRouterAddress = payable(address(0xfEe8d79961c529E06233fbF64F96454c2656BFEE)); // TODO: update this with the actual fee router address

        // Define initial permissioned hypernodes
        address[] memory initialPermissionedHypernodes = new address[](2);
        initialPermissionedHypernodes[0] = address(0xbeEF58c34ab8E6CF9F27359d934648DFd630BeeF); // Replace with actual addresses

        address owner = address(0x82bdA835Ab91D3F38Cb291030A5B0e6Dff086d44);

        console.log("Deploying RiftExchange...");
        // TODO: Update deploy script for new contract

        // Deploy RiftExchange as a UUPS proxy
        bytes memory initializeData = abi.encodeCall(
            RiftExchange.initialize,
            (
                initialCheckpointHeight,
                initialBlockHash,
                initialRetargetBlockHash,
                initialChainwork,
                verifierContractAddress,
                depositTokenAddress,
                initialFeeRouterAddress,
                owner,
                verificationKeyHash,
                initialPermissionedHypernodes
            )
        );

        address proxy = Upgrades.deployUUPSProxy("RiftExchange.sol:RiftExchange", initializeData);

        console.log("RiftExchange proxy deployed at:", proxy);

        console.log("Deployment script finished.");
        */

        vm.stopBroadcast();
    }
}
