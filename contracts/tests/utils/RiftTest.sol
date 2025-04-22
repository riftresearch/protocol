// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {PRNG} from "./PRNG.sol";
import {Test} from "forge-std/src/Test.sol";
import {SP1MockVerifier} from "sp1-contracts/contracts/src/SP1MockVerifier.sol";
import {Vm} from "forge-std/src/Vm.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import "forge-std/src/console.sol";

import {HashLib} from "../../src/libraries/HashLib.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Events} from "../../src/libraries/Events.sol";
import {RiftExchange} from "../../src/RiftExchange.sol";
import {BitcoinLightClient} from "../../src/BitcoinLightClient.sol";
import {MockToken} from "./MockToken.sol";


contract RiftExchangeHarness is RiftExchange {
    using SafeTransferLib for address;
    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        uint16 _takerFeeBips,
        Types.BlockLeaf memory _tipBlockLeaf
    ) RiftExchange(_mmrRoot, _depositToken, _circuitVerificationKey, _verifier, _feeRouter, _takerFeeBips, _tipBlockLeaf) {}

    function depositLiquidity(Types.DepositLiquidityParams memory params) external returns (bytes32) {
        bytes32 hash = super._depositLiquidity(params);
        ERC20_BTC.safeTransferFrom(msg.sender, address(this), params.depositAmount);
        return hash;
    }
}

contract RiftTest is Test, PRNG {
    using HashLib for Types.DepositVault;
    using HashLib for Types.ProposedSwap;
    address exchangeOwner = address(0xbeef);
    RiftExchangeHarness public exchange;
    MockToken public mockToken;
    SP1MockVerifier public verifier;

    function setUp() public virtual {
        mockToken = new MockToken("Synthetic Bitcoin", "sBTC", 8);
        verifier = new SP1MockVerifier();

        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);

        exchange = new RiftExchangeHarness({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _takerFeeBips: 5,
            _tipBlockLeaf: initial_mmr_proof.blockLeaf
        });

        mockToken = MockToken(address(exchange.ERC20_BTC()));
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

    function _callTestUtilsGenerateFakeBlockWithConfirmationsMMRProof(
        uint32 height,
        uint32 confirmations
    ) internal returns (bytes memory) {
        string memory cmd = string.concat(
            "../target/release/sol-utils generate-fake-block-with-confirmations-mmr-proof --height ",
            vm.toString(height),
            " --confirmations ",
            vm.toString(confirmations)
        );
        return _callFFI(cmd);
    }

    function _callTestUtilsHashBlockLeaf(bytes memory leaf) internal returns (bytes32) {
        string memory cmd = string.concat(
            "../target/release/sol-utils hash-block-leaf --abi-encoded-leaf ",
            vm.toString(leaf)
        );
        return bytes32(_callFFI(cmd));
    }

    function _generateFakeBlockMMRProofFFI(uint32 height) public returns (Types.MMRProof memory) {
        bytes memory encodedProof = _callTestUtilsGenerateFakeBlockMMRProof(height);
        Types.MMRProof memory proof = abi.decode(encodedProof, (Types.MMRProof));
        return proof;
    }

    function _generateFakeBlockWithConfirmationsMMRProofFFI(
        uint32 height,
        uint32 confirmations
    ) public returns (Types.MMRProof memory, Types.MMRProof memory) {
        bytes memory combinedEncodedProofs = _callTestUtilsGenerateFakeBlockWithConfirmationsMMRProof(
            height,
            confirmations
        );
        Types.ReleaseMMRProof memory releaseProof = abi.decode(combinedEncodedProofs, (Types.ReleaseMMRProof));
        return (releaseProof.proof, releaseProof.tipProof);
    }

    function _hashBlockLeafFFI(Types.BlockLeaf memory leaf) public returns (bytes32) {
        bytes memory encodedLeaf = abi.encode(leaf);
        bytes32 hashedLeaf = _callTestUtilsHashBlockLeaf(encodedLeaf);
        return hashedLeaf;
    }

    function _getMockProof() internal pure returns (bytes memory, bytes memory) {
        bytes memory proof = new bytes(0);
        bytes memory compressedBlockLeaves = abi.encode("compressed leaves");
        return (proof, compressedBlockLeaves);
    }

    function _generateBtcPayoutScriptPubKey() internal returns (bytes22) {
        return bytes22(bytes.concat(bytes2(0x0014), keccak256(abi.encode(_random()))));
    }

    function _extractSingleVaultFromLogs(Vm.Log[] memory logs) internal pure returns (Types.DepositVault memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == Events.VaultsUpdated.selector) {
                return abi.decode(logs[i].data, (Types.DepositVault[]))[0];
            }
        }
        revert("Vault not found");
    }

    function _extractSingleSwapFromLogs(Vm.Log[] memory logs) internal pure returns (Types.ProposedSwap memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == Events.SwapsUpdated.selector) {
                return abi.decode(logs[i].data, (Types.ProposedSwap[]))[0];
            }
        }
        revert("Swap not found");
    }

    function _depositLiquidityWithAssertions(
        uint256 depositAmount,
        uint64 expectedSats,
        uint8 confirmationBlocks
    ) internal returns (Types.DepositVault memory) {
        // [1] mint and approve deposit token
        mockToken.mint(address(this), depositAmount);
        mockToken.approve(address(exchange), depositAmount);

        // [2] generate a scriptPubKey starting with a valid P2WPKH prefix (0x0014)
        bytes22 btcPayoutScriptPubKey = _generateBtcPayoutScriptPubKey();

        bytes32 depositSalt = bytes32(keccak256(abi.encode(_random())));

        Types.MMRProof memory mmr_proof = _generateFakeBlockMMRProofFFI(0);

        // [3] test deposit
        vm.recordLogs();
        Types.DepositLiquidityParams memory args = Types.DepositLiquidityParams({
            base: Types.BaseDepositLiquidityParams({
                btcPayoutScriptPubKey: btcPayoutScriptPubKey,
                depositSalt: depositSalt,
                confirmationBlocks: confirmationBlocks,
                safeBlockLeaf: mmr_proof.blockLeaf,
                depositOwnerAddress: address(this)
            }),
            specifiedPayoutAddress: address(this),
            depositAmount: depositAmount,
            expectedSats: expectedSats,
            safeBlockSiblings: mmr_proof.siblings,
            safeBlockPeaks: mmr_proof.peaks
        });

        exchange.depositLiquidity(args);

        // [4] grab the logs, find the vault
        Types.DepositVault memory createdVault = _extractSingleVaultFromLogs(vm.getRecordedLogs());
        uint256 vaultIndex = exchange.getVaultHashesLength() - 1;
        bytes32 _hash = exchange.getVaultHash(vaultIndex);

        // [5] verify "offchain" calculated hash matches stored vault hash
        bytes32 offchainHash = createdVault.hash();
        assertEq(offchainHash, _hash, "Offchain vault hash should match");

        // [6] verify vault index
        assertEq(createdVault.vaultIndex, vaultIndex, "Vault index should match");

        // [7] verify caller has no balance left
        assertEq(mockToken.balanceOf(address(this)), 0, "Caller should have no balance left");

        // [8] verify owner address
        assertEq(createdVault.ownerAddress, address(this), "Owner address should match");
        return createdVault;
    }
}
