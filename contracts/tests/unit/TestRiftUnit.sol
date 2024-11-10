// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BitcoinLightClientUpgradeable} from "../../src/BitcoinLightClientUpgradeable.sol";
import {RiftExchange} from "../../src/RiftExchange.sol";
import {RiftTest} from "../utils/RiftTest.sol";

contract RiftExchangeUnitTest is RiftTest {
    // Test that depositLiquidity appends a new commitment to the vaultCommitments array
    function testFuzz_depositLiquidity(uint256 depositAmount, uint64 expectedSats, uint256) public {
        // [0] bound deposit amount & expected sats
        depositAmount = bound(depositAmount, exchange.MIN_DEPOSIT_AMOUNT(), type(uint64).max);
        expectedSats = uint64(bound(expectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max));
        _depositLiquidityWithAssertions(depositAmount, expectedSats);
    }

    function testFuzz_depositLiquidityWithOverwrite(
        uint256 initialDepositAmount,
        uint64 expectedSats,
        uint256 toBeOverwrittenInitialDepositAmount,
        uint64 toBeOverwrittenExpectedSats,
        uint256
    ) public {
        // [0] bound deposit amounts & expected sats
        initialDepositAmount = bound(initialDepositAmount, exchange.MIN_DEPOSIT_AMOUNT(), type(uint64).max);
        expectedSats = uint64(bound(expectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max));
        toBeOverwrittenInitialDepositAmount = bound(
            toBeOverwrittenInitialDepositAmount,
            exchange.MIN_DEPOSIT_AMOUNT(),
            type(uint64).max
        );
        toBeOverwrittenExpectedSats = uint64(
            bound(toBeOverwrittenExpectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max)
        );

        // [1] create initial deposit
        RiftExchange.DepositVault memory fullVault = _depositLiquidityWithAssertions(
            toBeOverwrittenInitialDepositAmount,
            toBeOverwrittenExpectedSats
        );

        // [2] warp and withdraw to empty the vault
        vm.warp(block.timestamp + exchange.DEPOSIT_LOCKUP_PERIOD());
        vm.recordLogs();
        exchange.withdrawLiquidity({vault: fullVault});
        RiftExchange.DepositVault memory emptyVault = _extractVaultFromLogs(vm.getRecordedLogs());

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
            overwriteVault: emptyVault
        });

        // [6] grab the logs, find the new vault
        RiftExchange.DepositVault memory overwrittenVault = _extractVaultFromLogs(vm.getRecordedLogs());
        bytes32 commitment = exchange.getVaultCommitment(emptyVault.vaultIndex);

        // [7] verify "offchain" calculated commitment matches stored vault commitment
        bytes32 offchainCommitment = exchange.hashDepositVault(overwrittenVault);
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
        depositAmount = bound(depositAmount, exchange.MIN_DEPOSIT_AMOUNT(), type(uint64).max);
        expectedSats = uint64(bound(expectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max));
        withdrawalDelay = bound(withdrawalDelay, exchange.DEPOSIT_LOCKUP_PERIOD(), 365 days);

        // [1] create initial deposit and get vault
        RiftExchange.DepositVault memory vault = _depositLiquidityWithAssertions(depositAmount, expectedSats);
        uint256 initialBalance = mockUSDT.balanceOf(address(this));
        uint256 expectedWithdrawAmount = vault.depositAmount;

        // [2] warp to future time after lockup period
        vm.warp(block.timestamp + withdrawalDelay);

        // [3] withdraw and capture updated vault from logs
        vm.recordLogs();
        exchange.withdrawLiquidity(vault);
        RiftExchange.DepositVault memory updatedVault = _extractVaultFromLogs(vm.getRecordedLogs());

        // [4] verify updated vault commitment matches stored commitment
        bytes32 storedCommitment = exchange.getVaultCommitment(vault.vaultIndex);
        bytes32 calculatedCommitment = exchange.hashDepositVault(updatedVault);
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
        BitcoinLightClientUpgradeable.BlockLeaf memory leaf
    ) internal view returns (bytes32[] memory proof, bytes32 root, bytes32 leafHash) {
        // This represents a simple Merkle tree:
        //       root (0xabc...)
        //      /          \
        //   leaf          0x123...
        //   (block)       (other branch)

        leafHash = exchange.buildLeafCommitment(leaf);

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
        depositAmount = bound(depositAmount, exchange.MIN_DEPOSIT_AMOUNT(), type(uint64).max);
        expectedSats = uint64(bound(expectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max));
        numVaults = uint8(bound(numVaults, 1, 100)); // Reasonable max to avoid gas issues
        uint256 totalSwapAmount = depositAmount * numVaults;
        uint256 totalSwapFee = exchange.calculateFeeFromAmount(totalSwapAmount);

        // [1] create multiple deposit vaults
        RiftExchange.DepositVault[] memory vaults = new RiftExchange.DepositVault[](numVaults);
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
        RiftExchange.ProposedSwap memory createdSwap = _extractSwapFromLogs(vm.getRecordedLogs());
        uint256 swapIndex = exchange.getSwapCommitmentsLength() - 1;
        bytes32 commitment = exchange.getSwapCommitment(swapIndex);

        // [5] verify swap details
        assertEq(createdSwap.swapIndex, swapIndex, "Swap index should match");
        assertEq(createdSwap.specifiedPayoutAddress, address(this), "Payout address should match");
        assertEq(createdSwap.totalSwapAmount, totalSwapAmount, "Swap amount should match");
        assertEq(createdSwap.totalSwapFee, totalSwapFee, "Swap fee should match");
        assertEq(uint8(createdSwap.state), uint8(RiftExchange.SwapState.Proved), "Swap should be in Proved state");

        // [6] verify commitment
        bytes32 offchainCommitment = exchange.hashSwap(createdSwap);
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
        depositAmount = bound(depositAmount, exchange.MIN_DEPOSIT_AMOUNT(), type(uint64).max);
        expectedSats = uint64(bound(expectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max));
        numVaults = uint8(bound(numVaults, 1, 100)); // Reasonable max to avoid gas issues
        totalSwapAmount = bound(totalSwapAmount, exchange.MIN_DEPOSIT_AMOUNT(), depositAmount * numVaults);
        uint256 totalSwapFee = exchange.calculateFeeFromAmount(totalSwapAmount);

        // [1] create multiple deposit vaults
        RiftExchange.DepositVault[] memory vaults = new RiftExchange.DepositVault[](numVaults);
        for (uint256 i = 0; i < numVaults; i++) {
            vaults[i] = _depositLiquidityWithAssertions(depositAmount, expectedSats);
        }

        uint64 proposedBlockHeight = 100;
        uint256 proposedBlockCumulativeChainwork = 1000;
        bytes32 proposedBlockHash = keccak256("proposed block");

        // [2] generate valid merkle proof components
        (bytes32[] memory inclusionProof, bytes32 mmrRoot, ) = _generateSimpleValidInclusionProof(
            BitcoinLightClientUpgradeable.BlockLeaf({
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
        RiftExchange.ProposedSwap memory createdSwap = _extractSwapFromLogs(vm.getRecordedLogs());

        // [5] warp past challenge period
        vm.warp(block.timestamp + exchange.CHALLENGE_PERIOD());

        // [6] record initial balances
        uint256 initialBalance = mockUSDT.balanceOf(address(this));
        uint256 initialFeeBalance = exchange.accumulatedFeeBalance();

        // [7] release liquidity using our valid merkle proof
        vm.recordLogs();
        exchange.releaseLiquidity(createdSwap, inclusionProof, vaults);

        // [8] verify swap was marked as completed
        RiftExchange.ProposedSwap memory updatedSwap = _extractSwapFromLogs(vm.getRecordedLogs());
        assertEq(uint8(updatedSwap.state), uint8(RiftExchange.SwapState.Completed), "Swap should be completed");

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
            RiftExchange.DepositVault memory emptyVault = vaults[i];
            emptyVault.depositAmount = 0;
            emptyVault.depositFee = 0;
            bytes32 expectedCommitment = exchange.hashDepositVault(emptyVault);
            assertEq(vaultCommitment, expectedCommitment, "Vault should be empty");
        }
    }
}
