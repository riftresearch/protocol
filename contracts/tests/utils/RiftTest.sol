// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.4;
import "../../src/interfaces/IRiftExchange.sol";

import {HelperTypes} from "../utils/HelperTypes.sol";
import {PRNG} from "./PRNG.sol";
import {Test} from "forge-std/src/Test.sol";
import {SP1MockVerifier} from "sp1-contracts/contracts/src/SP1MockVerifier.sol";
import {Vm} from "forge-std/src/Vm.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import "forge-std/src/console.sol";

import {HashLib} from "../../src/libraries/HashLib.sol";
import {RiftExchange} from "../../src/RiftExchange.sol";
import {BitcoinLightClient} from "../../src/BitcoinLightClient.sol";
import {SyntheticBTC} from "./SyntheticBTC.sol";

contract RiftExchangeHarness is RiftExchange {
    using SafeTransferLib for address;

    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        uint16 _takerFeeBips,
        BlockLeaf memory _tipBlockLeaf
    )
        RiftExchange(
            _mmrRoot,
            _depositToken,
            _circuitVerificationKey,
            _verifier,
            _feeRouter,
            _takerFeeBips,
            _tipBlockLeaf
        )
    {}

    function createOrder(CreateOrderParams memory params) external {
        super._createOrder(params);
        syntheticBitcoin.safeTransferFrom(msg.sender, address(this), params.depositAmount);
    }
}

contract RiftTest is Test, PRNG {
    using HashLib for Order;
    using HashLib for Payment;
    address exchangeOwner = address(0xbeef);
    RiftExchangeHarness public exchange;
    SyntheticBTC public syntheticBTC;
    SP1MockVerifier public verifier;

    function setUp() public virtual {
        syntheticBTC = new SyntheticBTC();
        verifier = new SP1MockVerifier();

        HelperTypes.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);

        exchange = new RiftExchangeHarness({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(syntheticBTC),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _takerFeeBips: 5,
            _tipBlockLeaf: initial_mmr_proof.blockLeaf
        });

        syntheticBTC = SyntheticBTC(address(exchange.syntheticBitcoin()));
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

    function _generateFakeBlockMMRProofFFI(uint32 height) public returns (HelperTypes.MMRProof memory) {
        bytes memory encodedProof = _callTestUtilsGenerateFakeBlockMMRProof(height);
        HelperTypes.MMRProof memory proof = abi.decode(encodedProof, (HelperTypes.MMRProof));
        return proof;
    }

    function _generateFakeBlockWithConfirmationsMMRProofFFI(
        uint32 height,
        uint32 confirmations
    ) public returns (HelperTypes.MMRProof memory, HelperTypes.MMRProof memory) {
        bytes memory combinedEncodedProofs = _callTestUtilsGenerateFakeBlockWithConfirmationsMMRProof(
            height,
            confirmations
        );
        HelperTypes.ReleaseMMRProof memory releaseProof = abi.decode(
            combinedEncodedProofs,
            (HelperTypes.ReleaseMMRProof)
        );
        return (releaseProof.proof, releaseProof.tipProof);
    }

    function _hashBlockLeafFFI(BlockLeaf memory leaf) public returns (bytes32) {
        bytes memory encodedLeaf = abi.encode(leaf);
        bytes32 hashedLeaf = _callTestUtilsHashBlockLeaf(encodedLeaf);
        return hashedLeaf;
    }

    function _getMockProof() internal pure returns (bytes memory, bytes memory) {
        bytes memory proof = new bytes(0);
        bytes memory compressedBlockLeaves = abi.encode("compressed leaves");
        return (proof, compressedBlockLeaves);
    }

    function _generateBtcPayoutScriptPubKey() internal returns (bytes memory) {
        return bytes.concat(bytes2(0x0014), bytes20(keccak256(abi.encode(_random()))));
    }

    function _extractSingleOrderFromLogs(Vm.Log[] memory logs) internal pure returns (Order memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IRiftExchange.OrdersUpdated.selector) {
                return abi.decode(logs[i].data, (Order[]))[0];
            }
        }
        revert("Order not found");
    }

    function _extractSinglePaymentFromLogs(Vm.Log[] memory logs) internal pure returns (Payment memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IRiftExchange.PaymentsUpdated.selector) {
                return abi.decode(logs[i].data, (Payment[]))[0];
            }
        }
        revert("Payment not found");
    }

    function _createOrderWithAssertions(
        uint256 depositAmount,
        uint64 expectedSats,
        uint8 confirmationBlocks
    ) internal returns (Order memory) {
        // [1] mint and approve deposit token
        syntheticBTC.mint(address(this), depositAmount);
        syntheticBTC.approve(address(exchange), depositAmount);

        // [2] generate a scriptPubKey starting with a valid P2WPKH prefix (0x0014)
        bytes memory btcPayoutScriptPubKey = _generateBtcPayoutScriptPubKey();

        bytes32 depositSalt = bytes32(keccak256(abi.encode(_random())));

        HelperTypes.MMRProof memory mmr_proof = _generateFakeBlockMMRProofFFI(0);

        // [3] test deposit
        vm.recordLogs();
        CreateOrderParams memory args = CreateOrderParams({
            base: BaseCreateOrderParams({
                bitcoinScriptPubKey: btcPayoutScriptPubKey,
                salt: depositSalt,
                confirmationBlocks: confirmationBlocks,
                safeBlockLeaf: mmr_proof.blockLeaf,
                owner: address(this)
            }),
            designatedReceiver: address(this),
            depositAmount: depositAmount,
            expectedSats: expectedSats,
            safeBlockSiblings: mmr_proof.siblings,
            safeBlockPeaks: mmr_proof.peaks
        });

        exchange.createOrder(args);

        // [4] grab the logs, find the vault
        Order memory createdOrder = _extractSingleOrderFromLogs(vm.getRecordedLogs());
        uint256 orderIndex = exchange.getTotalOrders() - 1;
        bytes32 _hash = exchange.orderHashes(orderIndex);

        // [5] verify "offchain" calculated hash matches stored vault hash
        bytes32 offchainHash = createdOrder.hash();
        assertEq(offchainHash, _hash, "Offchain order hash should match");

        // [6] verify order index
        assertEq(createdOrder.index, orderIndex, "Order index should match");

        // [7] verify caller has no balance left
        assertEq(syntheticBTC.balanceOf(address(this)), 0, "Caller should have no balance left");

        // [8] verify owner address
        assertEq(createdOrder.owner, address(this), "Owner address should match");
        return createdOrder;
    }
}
