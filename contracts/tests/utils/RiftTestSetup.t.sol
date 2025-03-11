// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RiftExchange} from "../../src/RiftExchange.sol";
import {RiftReactor} from "../../src/RiftReactor.sol";
import {Types} from "../../src/libraries/Types.sol";

import {Test} from "forge-std/src/Test.sol";
import {SP1MockVerifier} from "sp1-contracts/contracts/src/SP1MockVerifier.sol";

import {MockToken} from "./MockToken.sol";

contract RiftReactorMock is RiftReactor {
    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        Types.BlockLeaf memory _tipBlockLeaf,
        address _cbbtc_address
    )
        RiftReactor(
            _mmrRoot,
            _depositToken,
            _circuitVerificationKey,
            _verifier,
            _feeRouter,
            _tipBlockLeaf,
            _cbbtc_address
        )
    {}

    function computeBond(uint256 depositAmount) public pure returns (uint96 requiredBond) {
        return _computeBond(depositAmount);
    }

    function computeAuctionSats(Types.DutchAuctionInfo memory info) public view returns (uint256 expectedSats) {
        return _computeAuctionSats(info);
    }
}

contract RiftTestSetup is Test {
    address exchangeOwner = address(0xbeef);
    MockToken public mockToken;
    MockToken public cbBTC;
    SP1MockVerifier public verifier;
    RiftReactorMock public riftReactor;

    function setUp() public virtual {
        mockToken = new MockToken("Mock Token", "MTK", 6);
        verifier = new SP1MockVerifier();

        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
        cbBTC = new MockToken("Mock cbBTC", "cbBTC", 8);

        riftReactor = new RiftReactorMock({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _tipBlockLeaf: initial_mmr_proof.blockLeaf,
            _cbbtc_address: address(cbBTC)
        });

        mockToken = MockToken(address(riftReactor.DEPOSIT_TOKEN()));

        // Mint tokens to the test contract so it can approve depositBond.
        // Adjust the mint amount as needed.
        mockToken.mint(address(this), 1_000_000);
        cbBTC.mint(address(this), 1_000_000);
    }

    function _callFFI(string memory cmd) internal returns (bytes memory) {
        string[] memory curlInputs = new string[](3);
        curlInputs[0] = "bash";
        curlInputs[1] = "-c";
        curlInputs[2] = cmd;
        return vm.ffi(curlInputs);
    }

    function _callTestUtilsGenerateFakeBlockMMRProof(uint32 height) internal returns (bytes memory) {
        string memory cmd = string.concat(
            "../target/release/sol-utils generate-fake-block-mmr-proof --height ",
            vm.toString(height)
        );
        return _callFFI(cmd);
    }

    function _generateFakeBlockMMRProofFFI(uint32 height) public returns (Types.MMRProof memory) {
        bytes memory encodedProof = _callTestUtilsGenerateFakeBlockMMRProof(height);
        Types.MMRProof memory proof = abi.decode(encodedProof, (Types.MMRProof));
        return proof;
    }
}
