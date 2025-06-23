// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

import "forge-std/src/Script.sol";
import "forge-std/src/console.sol";
import "../src/RiftExchange.sol";
import {HelperTypes} from "../tests/utils/HelperTypes.t.sol";
// createx salts scoped to alpinevm.eth as caller (5 leading bytes)
/*
0x42563cb907629373eb1f507c30577d49483128e10087b33b6f353f0701fd6e42 => 0x0000000000eb638addaf4e073f876f376d031698 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1002a88426fb4023401e1d8f5 => 0x000000000066809871f72892165f4cff460ce545 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10065a30cca099571023bd286 => 0x000000000074a41b411f00cd3edb4d2c3a4877c7 (5 / 6)
0x42563cb907629373eb1f507c30577d49483128e100afeed0ffbb8a810273d7eb => 0x00000000001c28db2d76fa934acd1190d15c2843 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1001641be095a76ce01a7c9a3 => 0x0000000000fa12d9d365285a79ad848479e6e119 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1004e3b86d812ddbf02ead917 => 0x000000000070e15c059811b6aaa0ceae699fd8b2 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100884832254b65d9007f11d2 => 0x0000000000c6c6f13af54cbb68fb53b685748ee5 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10054b97ce96bf15001d7213c => 0x000000000086c7c920ab64316ae381b03ff2ae38 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100cd966fe2107f5403b8d618 => 0x000000000013923c5bf346793bb5e6a832cb6df3 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1002d4c9ef11f551e00b795cd => 0x0000000000572a3df60b8bbbbffe856545050ec2 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10099c5bb5dcdaf4c03520af1 => 0x00000000005728065b618defb3686adf847f178d (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10051ac241ee661c0019f4ea4 => 0x00000000002be7952a8bebb19fec637ee97ea681 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10074e2d64536978f013f2252 => 0x0000000000692c19b7fa3a253f8bddf0a4c70e54 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100aa021dcb9ce3710171b77e => 0x0000000000c53c8a1cda04ef2c0f2274e5254c33 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100e2c2b22d10618a35e887f7 => 0x000000000033b09105acb109df18ba2cb3f5e288 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1009a2378d8d70dac21e2ffdf => 0x0000000000d0540e81131f6bfe5d8565c293e58f (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1003e4c5564cb029d27af0dd6 => 0x0000000000f279f38e52e178f0c7a68bd92a757c (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100455645ea9448a56abf4692 => 0x00000000004af2eda95aa7db53795987008deea6 (5 / 6)
0x42563cb907629373eb1f507c30577d49483128e100609ded21cda1ad66102b44 => 0x00000000004d528716fd29b88abba4e2c3b14d8f (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100bb8a7e96980dc614209241 => 0x00000000001b047bb5c1d0b20cabf95172f8d794 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1001be7871abf89db31ea2fab => 0x00000000009209e8feaf3f870f3659731e32b05d (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10022eac8b1a71df661bcf6cd => 0x0000000000f36ee08bbc6ed347f87d1c49b948ed (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100d2333849d4334916187f7f => 0x00000000006e67e1f4ed1a14f2cb7d7413f8a918 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10098193355dac5ca4b1f2bfa => 0x0000000000693bf25add0c36e173be0fac7d6c94 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1003f789160e470bc20581196 => 0x0000000000b541435c4ec49c8fe433d082609bf3 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10024618b9a1c4c974383ae5c => 0x0000000000380bda0628d72b2eaf01483a0eb3ab (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10097743fa30c05b04dc43f81 => 0x00000000005a86ea3aca96c29aa704989d86e41d (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100683bd03e4e66db6672fc6b => 0x0000000000cb897d24e9232916a2a759e638a964 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100a8584286ce5add3b7d87a2 => 0x000000000039156d58c0d209ede7b0a30dff460c (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10019f11b15fdac226b9df429 => 0x0000000000f0c46b981980b8e8edb3b33522c84a (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1000a72b708e877724f689c8f => 0x000000000096f4b5697e47cd6fc5a10ecdab1ade (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100c70c54b3e0f4ad3c2fe307 => 0x00000000003e405919c68656cb86d10179c71476 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1009d1abc4a4929182a5096d4 => 0x00000000009d2d442b1d6fd7b04f1389b11dd4b5 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1009d6f0a8c25f35d31572a07 => 0x0000000000e6d5eba97b5c71eb273a7f446d3a40 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1007a95ebf0aafec448b7c66d => 0x0000000000e61fcd09c0de0faccd9c3364496967 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100a50627c270d89b69ab6ffc => 0x00000000000318c85513f0e023a783bcc644501d (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100638f67277b26d805e7b158 => 0x000000000045881d03d534a34cb67f410c43b43c (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100ed6bbda96d36b233680351 => 0x00000000007e0bfcb403fde775ae12e5e6e4b797 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10091af4a425944f53afec64b => 0x0000000000c41ece410e17ab388fbbc70da9273b (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100390bf8c934572c3cc058f4 => 0x00000000006570ad7b74cc7e9aed8ff154028523 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10018c0decfd160573c3fb75f => 0x0000000000ee1b7f34aca77d0feda076cd309acd (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10074ebbfa659b9225db8774e => 0x00000000006f918bafac136cc8d7fe7de879aa06 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100ca9a6b7b9aeb28311746c2 => 0x000000000071d60944d9657e3bd9a0dbb6ed4bc9 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100ec46fd74bf14d94a24782b => 0x0000000000b8753dad19ad45f0c98a3cd05e4284 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10013c6a815a43dfb48944f2b => 0x0000000000317d01ea4dae2e96dbf973e4972edf (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100eda7edf0f3c7580f7dc028 => 0x0000000000eb4a40e3b699426fa5a6e6ed135023 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100feb4b06b77f0f63ebff568 => 0x000000000019c306ee2a917fac2e091ea77b27cb (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100de7c56747410963ba21d80 => 0x00000000000ac90e4171040cd083380381493d9c (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10024bccf7c4f77e86ab356de => 0x00000000008d9f0edf031ca99a1132ebc580bf25 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e1004e17a6ae8d7f6810ffb229 => 0x00000000005ef839a6f4dbc119604d2047da0908 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e10020ff019d6951521ad64eb7 => 0x0000000000cd1397412b22c6851a702b00b561b2 (5 / 6)
0x42563cb907629373eb1f507c30577d49483128e1006396ffa2a83cb154ae6421 => 0x0000000000d6337b96b97eddf0072216e987e5b0 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100fec943093966ab60998ca0 => 0x0000000000827ec0b8a516b50574340da2141d8c (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100fe20ff894e3b8b1701e5b2 => 0x0000000000cddca7f6b086792a4844c410079ec7 (5 / 5)
0x42563cb907629373eb1f507c30577d49483128e100d4f5191a7fe8a1612f512f => 0x0000000000b58da8056a216cdd10be958ffbcfdc (5 / 5)
-----
6 leading bytes
0x42563cb907629373eb1f507c30577d49483128e100ba7bca5feae7fc02917107 => 0x000000000000709712428da55d2cffc42c08bc50 (6 / 6)
0x42563cb907629373eb1f507c30577d49483128e100e71f097740f27a147239fe => 0x000000000000f37a8dc11482d49f239cbe906d10 (6 / 6)
0x42563cb907629373eb1f507c30577d49483128e1004584b1ecbed14b65add505 => 0x0000000000005c881701a23b1ef7fff283a4dc77 (6 / 6)
*/


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
        
        // TODO: Add authorized hypernodes after deployment
        // riftExchange.addHypernode(hypernodeAddress1);
        // riftExchange.addHypernode(hypernodeAddress2);
        */

        vm.stopBroadcast();
    }
}
