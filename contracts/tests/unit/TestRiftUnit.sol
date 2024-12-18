// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BitcoinLightClient} from "../../src/BitcoinLightClient.sol";
import {Constants} from "../../src/libraries/Constants.sol";
import {LightClientVerificationLib} from "../../src/libraries/LightClientVerificationLib.sol";
import "../../src/libraries/CommitmentVerificationLib.sol";
import {Types} from "../../src/libraries/Types.sol";
import {MarketLib} from "../../src/libraries/MarketLib.sol";
import {RiftExchange} from "../../src/RiftExchange.sol";
import {RiftTest} from "../utils/RiftTest.sol";
import "forge-std/console.sol";

contract RiftExchangeUnitTest is RiftTest {
    // hacky way to get nice formatting for the vault in logs
    event VaultLog(Types.DepositVault vault);
    event VaultCommitmentLog(bytes32 vaultCommitment);
    event LogVaults(Types.DepositVault[] vaults);

    // functional clone of validateDepositVaultCommitments, but doesn't attempt to validate the vaults existence in storage
    // used to generate test data for circuits
    function generateDepositVaultCommitment(Types.DepositVault[] memory vaults) internal pure returns (bytes32) {
        bytes32[] memory vaultHashes = new bytes32[](vaults.length);
        for (uint256 i = 0; i < vaults.length; i++) {
            vaultHashes[i] = CommitmentVerificationLib.hashDepositVault(vaults[i]);
        }
        return EfficientHashLib.hash(vaultHashes);
    }

    // use to generate test data for circuits
    function test_vaultCommitments(Types.DepositVault memory vault, uint256) public {
        // uint64 max here so it can be set easily in rust
        bound(vault.vaultIndex, 0, uint256(type(uint64).max));
        bytes32 vault_commitment = CommitmentVerificationLib.hashDepositVault(vault);
        emit VaultLog(vault);
        emit VaultCommitmentLog(vault_commitment);
    }

    function constrainVault(
        Types.DepositVault memory vault,
        uint64 maxValue
    ) internal pure returns (Types.DepositVault memory) {
        return
            Types.DepositVault({
                vaultIndex: vault.vaultIndex % maxValue,
                depositTimestamp: vault.depositTimestamp % maxValue,
                depositAmount: vault.depositAmount % maxValue,
                depositFee: vault.depositFee % maxValue,
                expectedSats: vault.expectedSats % maxValue,
                btcPayoutScriptPubKey: vault.btcPayoutScriptPubKey,
                specifiedPayoutAddress: vault.specifiedPayoutAddress,
                ownerAddress: vault.ownerAddress,
                nonce: vault.nonce
            });
    }

    // use to generate test data for circuits
    function test_aggregateVaultCommitments(
        Types.DepositVault[1] memory singleVaultSet,
        Types.DepositVault[2] memory twoVaultSet,
        uint256
    ) public {
        uint64 maxValue = type(uint64).max;

        Types.DepositVault[] memory singleVaultSetArray = new Types.DepositVault[](1);
        singleVaultSetArray[0] = constrainVault(singleVaultSet[0], maxValue);
        bytes32 singleVaultCommitment = generateDepositVaultCommitment(singleVaultSetArray);
        emit LogVaults(singleVaultSetArray);
        emit VaultCommitmentLog(singleVaultCommitment);

        Types.DepositVault[] memory twoVaultSetArray = new Types.DepositVault[](2);
        twoVaultSetArray[0] = constrainVault(twoVaultSet[0], maxValue);
        twoVaultSetArray[1] = constrainVault(twoVaultSet[1], maxValue);
        bytes32 twoVaultCommitment = generateDepositVaultCommitment(twoVaultSetArray);
        emit LogVaults(twoVaultSetArray);
        emit VaultCommitmentLog(twoVaultCommitment);
    }

    // Test that depositLiquidity appends a new commitment to the vaultCommitments array
    function testFuzz_depositLiquidity(uint256 depositAmount, uint64 expectedSats, uint256) public {
        // [0] bound deposit amount & expected sats
        depositAmount = bound(depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        expectedSats = uint64(bound(expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        _depositLiquidityWithAssertions(depositAmount, expectedSats);
    }

    function testFuzz_depositLiquidityWithOverwrite(
        uint256 initialDepositAmount,
        uint64 expectedSats,
        uint256 toBeOverwrittenInitialDepositAmount,
        uint64 toBeOverwrittenExpectedSats,
        bytes32 depositSalt,
        uint256
    ) public {
        // [0] bound deposit amounts & expected sats
        initialDepositAmount = bound(initialDepositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        expectedSats = uint64(bound(expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        toBeOverwrittenInitialDepositAmount = bound(
            toBeOverwrittenInitialDepositAmount,
            Constants.MIN_DEPOSIT_AMOUNT,
            type(uint64).max
        );
        toBeOverwrittenExpectedSats = uint64(
            bound(toBeOverwrittenExpectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max)
        );

        // [1] create initial deposit
        Types.DepositVault memory fullVault = _depositLiquidityWithAssertions(
            toBeOverwrittenInitialDepositAmount,
            toBeOverwrittenExpectedSats
        );

        // [2] warp and withdraw to empty the vault
        vm.warp(block.timestamp + Constants.DEPOSIT_LOCKUP_PERIOD);
        vm.recordLogs();
        exchange.withdrawLiquidity({vault: fullVault});
        Types.DepositVault memory emptyVault = _extractVaultFromLogs(vm.getRecordedLogs());

        // [3] burn the USDT withdrawn from the vault
        mockUSDT.transfer(address(0), mockUSDT.balanceOf(address(this)));

        // [4] prepare for overwrite deposit
        mockUSDT.mint(address(this), initialDepositAmount);
        mockUSDT.approve(address(exchange), initialDepositAmount);

        // [5] perform overwrite deposit
        vm.recordLogs();
        exchange.depositLiquidityWithOverwrite({
            specifiedPayoutAddress: address(this),
            initialDepositAmount: initialDepositAmount,
            expectedSats: expectedSats,
            btcPayoutScriptPubKey: _generateBtcPayoutScriptPubKey(),
            overwriteVault: emptyVault,
            depositSalt: depositSalt
        });

        // [6] grab the logs, find the new vault
        Types.DepositVault memory overwrittenVault = _extractVaultFromLogs(vm.getRecordedLogs());
        bytes32 commitment = exchange.getVaultCommitment(emptyVault.vaultIndex);

        // [7] verify "offchain" calculated commitment matches stored vault commitment
        bytes32 offchainCommitment = CommitmentVerificationLib.hashDepositVault(overwrittenVault);
        assertEq(offchainCommitment, commitment, "Offchain vault commitment should match");

        // [8] verify vault index remains the same
        assertEq(overwrittenVault.vaultIndex, emptyVault.vaultIndex, "Vault index should match original");

        // [9] verify caller has no balance left
        assertEq(mockUSDT.balanceOf(address(this)), 0, "Caller should have no balance left");

        // [10] verify owner address
        assertEq(overwrittenVault.ownerAddress, address(this), "Owner address should match");
    }

    function testFuzz_withdrawLiquidity(
        uint256 depositAmount,
        uint64 expectedSats,
        uint256 withdrawalDelay,
        uint256
    ) public {
        // [0] bound inputs
        depositAmount = bound(depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        expectedSats = uint64(bound(expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        withdrawalDelay = bound(withdrawalDelay, Constants.DEPOSIT_LOCKUP_PERIOD, 365 days);

        // [1] create initial deposit and get vault
        Types.DepositVault memory vault = _depositLiquidityWithAssertions(depositAmount, expectedSats);
        uint256 initialBalance = mockUSDT.balanceOf(address(this));
        uint256 expectedWithdrawAmount = vault.depositAmount;

        // [2] warp to future time after lockup period
        vm.warp(block.timestamp + withdrawalDelay);

        // [3] withdraw and capture updated vault from logs
        vm.recordLogs();
        exchange.withdrawLiquidity(vault);
        Types.DepositVault memory updatedVault = _extractVaultFromLogs(vm.getRecordedLogs());

        // [4] verify updated vault commitment matches stored commitment
        bytes32 storedCommitment = exchange.getVaultCommitment(vault.vaultIndex);
        bytes32 calculatedCommitment = CommitmentVerificationLib.hashDepositVault(updatedVault);
        assertEq(calculatedCommitment, storedCommitment, "Vault commitment mismatch");

        // [5] verify vault is now empty
        assertEq(updatedVault.depositAmount, 0, "Updated vault should be empty");
        assertEq(updatedVault.vaultIndex, vault.vaultIndex, "Vault index should remain unchanged");

        // [6] verify tokens were transferred correctly
        assertEq(
            mockUSDT.balanceOf(address(this)),
            initialBalance + expectedWithdrawAmount,
            "Incorrect withdrawal amount"
        );
    }

    function _generateSimpleValidInclusionProof(
        Types.BlockLeaf memory leaf
    ) internal pure returns (bytes32[] memory proof, bytes32 root, bytes32 leafHash) {
        // This represents a simple Merkle tree:
        //       root (0xabc...)
        //      /          \
        //   leaf          0x123...
        //   (block)       (other branch)

        leafHash = LightClientVerificationLib.buildLeafCommitment(leaf);

        bytes32 rightBranch = keccak256(abi.encodePacked("right branch"));

        bytes32 leftNode = leafHash;
        bytes32 rightNode = rightBranch;

        if (uint256(leftNode) > uint256(rightNode)) {
            (leftNode, rightNode) = (rightNode, leftNode);
        }

        root = keccak256(abi.encodePacked(leftNode, rightNode));

        proof = new bytes32[](1);
        proof[0] = rightBranch;

        return (proof, root, leafHash);
    }

    function testFuzz_submitSwapProof(uint256 depositAmount, uint64 expectedSats, uint8 numVaults, uint256) public {
        // [0] bound inputs
        depositAmount = bound(depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        expectedSats = uint64(bound(expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        numVaults = uint8(bound(numVaults, 1, 100)); // Reasonable max to avoid gas issues
        uint256 totalSwapAmount = depositAmount * numVaults;
        uint256 totalSwapFee = MarketLib.calculateFeeFromAmount(totalSwapAmount);

        // [1] create multiple deposit vaults
        Types.DepositVault[] memory vaults = new Types.DepositVault[](numVaults);
        for (uint256 i = 0; i < numVaults; i++) {
            vaults[i] = _depositLiquidityWithAssertions(depositAmount, expectedSats);
        }

        // [2] create dummy proof data
        bytes32 proposedBlockHash = keccak256("proposed block");
        uint64 proposedBlockHeight = 100;
        uint256 proposedBlockCumulativeChainwork = 1000;
        bytes32 priorMmrRoot = exchange.mmrRoot();
        bytes32 newMmrRoot = keccak256("new mmr root");
        bytes memory proof = new bytes(0);
        bytes memory compressedBlockLeaves = abi.encode("compressed leaves");

        // [3] submit swap proof and capture logs
        vm.recordLogs();
        exchange.submitSwapProof({
            proposedBlockHash: proposedBlockHash,
            proposedBlockHeight: proposedBlockHeight,
            proposedBlockCumulativeChainwork: proposedBlockCumulativeChainwork,
            vaults: vaults,
            specifiedPayoutAddress: address(this),
            priorMmrRoot: priorMmrRoot,
            newMmrRoot: newMmrRoot,
            totalSwapFee: totalSwapFee,
            totalSwapAmount: totalSwapAmount,
            proof: proof,
            compressedBlockLeaves: compressedBlockLeaves
        });

        // [4] extract swap from logs
        Types.ProposedSwap memory createdSwap = _extractSwapFromLogs(vm.getRecordedLogs());
        uint256 swapIndex = exchange.getSwapCommitmentsLength() - 1;
        bytes32 commitment = exchange.getSwapCommitment(swapIndex);

        // [5] verify swap details
        assertEq(createdSwap.swapIndex, swapIndex, "Swap index should match");
        assertEq(createdSwap.specifiedPayoutAddress, address(this), "Payout address should match");
        assertEq(createdSwap.totalSwapAmount, totalSwapAmount, "Swap amount should match");
        assertEq(createdSwap.totalSwapFee, totalSwapFee, "Swap fee should match");
        assertEq(uint8(createdSwap.state), uint8(Types.SwapState.Proved), "Swap should be in Proved state");

        // [6] verify commitment
        bytes32 offchainCommitment = CommitmentVerificationLib.hashSwap(createdSwap);
        assertEq(offchainCommitment, commitment, "Offchain swap commitment should match");
    }

    function testFuzz_releaseLiquidity(
        uint256 depositAmount,
        uint64 expectedSats,
        uint256 totalSwapAmount,
        uint8 numVaults,
        uint256
    ) public {
        // [0] bound inputs
        depositAmount = bound(depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        expectedSats = uint64(bound(expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        numVaults = uint8(bound(numVaults, 1, 100)); // Reasonable max to avoid gas issues
        totalSwapAmount = bound(totalSwapAmount, Constants.MIN_DEPOSIT_AMOUNT, depositAmount * numVaults);
        uint256 totalSwapFee = MarketLib.calculateFeeFromAmount(totalSwapAmount);

        // [1] create multiple deposit vaults
        Types.DepositVault[] memory vaults = new Types.DepositVault[](numVaults);
        for (uint256 i = 0; i < numVaults; i++) {
            vaults[i] = _depositLiquidityWithAssertions(depositAmount, expectedSats);
        }

        uint64 proposedBlockHeight = 100;
        uint256 proposedBlockCumulativeChainwork = 1000;
        bytes32 proposedBlockHash = keccak256("proposed block");

        // [2] generate valid merkle proof components
        (bytes32[] memory inclusionProof, bytes32 mmrRoot, ) = _generateSimpleValidInclusionProof(
            Types.BlockLeaf({
                blockHash: proposedBlockHash,
                height: proposedBlockHeight,
                cumulativeChainwork: proposedBlockCumulativeChainwork
            })
        );
        bytes32 priorMmrRoot = exchange.mmrRoot();
        bytes32 newMmrRoot = mmrRoot; // Use our valid MMR root
        bytes memory proof = new bytes(0);
        bytes memory compressedBlockLeaves = abi.encode("compressed leaves");

        vm.recordLogs();
        exchange.submitSwapProof({
            proposedBlockHash: proposedBlockHash, // Use our valid block hash
            proposedBlockHeight: proposedBlockHeight,
            proposedBlockCumulativeChainwork: proposedBlockCumulativeChainwork,
            vaults: vaults,
            specifiedPayoutAddress: address(this),
            priorMmrRoot: priorMmrRoot,
            newMmrRoot: newMmrRoot,
            totalSwapFee: totalSwapFee,
            totalSwapAmount: totalSwapAmount,
            proof: proof,
            compressedBlockLeaves: compressedBlockLeaves
        });

        // [4] extract swap from logs
        Types.ProposedSwap memory createdSwap = _extractSwapFromLogs(vm.getRecordedLogs());

        // [5] warp past challenge period
        vm.warp(block.timestamp + Constants.CHALLENGE_PERIOD);

        // [6] record initial balances
        uint256 initialBalance = mockUSDT.balanceOf(address(this));
        uint256 initialFeeBalance = exchange.accumulatedFeeBalance();

        // [7] release liquidity using our valid merkle proof
        vm.recordLogs();
        exchange.releaseLiquidity(createdSwap, inclusionProof, vaults);

        // [8] verify swap was marked as completed
        Types.ProposedSwap memory updatedSwap = _extractSwapFromLogs(vm.getRecordedLogs());
        assertEq(uint8(updatedSwap.state), uint8(Types.SwapState.Completed), "Swap should be completed");

        // [9] verify funds were transferred correctly
        assertEq(
            mockUSDT.balanceOf(address(this)),
            initialBalance + totalSwapAmount,
            "Incorrect amount transferred to recipient"
        );
        assertEq(
            exchange.accumulatedFeeBalance(),
            initialFeeBalance + totalSwapFee,
            "Incorrect fee amount accumulated"
        );

        // [10] verify vaults were emptied
        for (uint256 i = 0; i < vaults.length; i++) {
            bytes32 vaultCommitment = exchange.getVaultCommitment(vaults[i].vaultIndex);
            Types.DepositVault memory emptyVault = vaults[i];
            emptyVault.depositAmount = 0;
            emptyVault.depositFee = 0;
            bytes32 expectedCommitment = CommitmentVerificationLib.hashDepositVault(emptyVault);
            assertEq(vaultCommitment, expectedCommitment, "Vault should be empty");
        }
    }
}
