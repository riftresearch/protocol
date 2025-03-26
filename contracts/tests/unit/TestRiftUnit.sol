// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BitcoinLightClient} from "../../src/BitcoinLightClient.sol";
import {Constants} from "../../src/libraries/Constants.sol";
import {LightClientVerificationLib} from "../../src/libraries/LightClientVerificationLib.sol";
import {VaultLib} from "../../src/libraries/VaultLib.sol";
import {Types} from "../../src/libraries/Types.sol";
import {RiftUtils} from "../../src/libraries/RiftUtils.sol";
import {RiftExchange} from "../../src/RiftExchange.sol";
import {RiftTest} from "../utils/RiftTest.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

import "forge-std/src/console.sol";

contract RiftExchangeUnitTest is RiftTest {
    // hacky way to get nice formatting for the vault in logs
    event VaultLog(Types.DepositVault vault);
    event VaultCommitmentLog(bytes32 vaultCommitment);
    event LogVaults(Types.DepositVault[] vaults);
    uint256 constant MAX_VAULTS = 2;

    // functional clone of validateDepositVaultCommitments, but doesn't attempt to validate the vaults existence in storage
    // used to generate test data for circuits
    // TODO: directly call the rust api from here as part of fuzzer
    function generateDepositVaultCommitment(Types.DepositVault[] memory vaults) internal pure returns (bytes32) {
        bytes32[] memory vaultHashes = new bytes32[](vaults.length);
        for (uint256 i = 0; i < vaults.length; i++) {
            vaultHashes[i] = VaultLib.hashDepositVault(vaults[i]);
        }
        return EfficientHashLib.hash(vaultHashes);
    }

    // use to generate test data for circuits
    // TODO: directly call the rust api from here as part of fuzzer
    function test_vaultCommitments(Types.DepositVault memory vault, uint256) public {
        // uint64 max here so it can be set easily in rust
        bound(vault.vaultIndex, 0, uint256(type(uint64).max));
        bytes32 vault_commitment = VaultLib.hashDepositVault(vault);
        emit VaultLog(vault);
        emit VaultCommitmentLog(vault_commitment);
    }

    // used to generate test data for circuits
    // TODO: directly call the rust api from here as part of fuzzer
    function test_blockLeafHasher() public pure {
        Types.BlockLeaf memory blockLeaf = Types.BlockLeaf({
            blockHash: hex"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            height: 0,
            cumulativeChainwork: 4295032833
        });

        console.log("blockLeaf fields");
        console.logBytes32(blockLeaf.blockHash);
        console.logBytes32(bytes32(uint256(blockLeaf.height)));
        console.logBytes32(bytes32(blockLeaf.cumulativeChainwork));

        bytes32 blockLeafHash = LightClientVerificationLib.buildLeafCommitment(blockLeaf);
        console.log("blockLeafHash");
        console.logBytes32(blockLeafHash);
    }

    function constrainVault(
        Types.DepositVault memory vault,
        uint64 maxValue
    ) internal pure returns (Types.DepositVault memory) {
        return
            Types.DepositVault({
                vaultIndex: vault.vaultIndex % maxValue,
                depositTimestamp: vault.depositTimestamp % maxValue,
                depositUnlockTimestamp: vault.depositUnlockTimestamp % maxValue,
                depositAmount: vault.depositAmount % maxValue,
                depositFee: vault.depositFee % maxValue,
                expectedSats: vault.expectedSats % maxValue,
                btcPayoutScriptPubKey: vault.btcPayoutScriptPubKey,
                specifiedPayoutAddress: vault.specifiedPayoutAddress,
                ownerAddress: vault.ownerAddress,
                salt: vault.salt,
                confirmationBlocks: vault.confirmationBlocks,
                attestedBitcoinBlockHeight: vault.attestedBitcoinBlockHeight % 2016
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
    function testFuzz_depositLiquidity(
        uint256 depositAmount,
        uint64 expectedSats,
        uint8 confirmationBlocks,
        uint256
    ) public {
        // [0] bound deposit amount & expected sats
        depositAmount = bound(depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        expectedSats = uint64(bound(expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        confirmationBlocks = uint8(bound(confirmationBlocks, Constants.MIN_CONFIRMATION_BLOCKS, type(uint8).max));
        _depositLiquidityWithAssertions(depositAmount, expectedSats, confirmationBlocks);
    }

    function testFuzz_depositLiquidityWithOverwrite(
        uint256 depositAmount,
        uint64 expectedSats,
        uint256 toBeOverwrittendepositAmount,
        uint64 toBeOverwrittenExpectedSats,
        bytes32 depositSalt,
        uint8 confirmationBlocks,
        uint256
    ) public {
        // [0] bound deposit amounts & expected sats
        depositAmount = bound(depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        expectedSats = uint64(bound(expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        confirmationBlocks = uint8(bound(confirmationBlocks, Constants.MIN_CONFIRMATION_BLOCKS, type(uint8).max));
        toBeOverwrittendepositAmount = bound(
            toBeOverwrittendepositAmount,
            Constants.MIN_DEPOSIT_AMOUNT,
            type(uint64).max
        );
        toBeOverwrittenExpectedSats = uint64(
            bound(toBeOverwrittenExpectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max)
        );

        // [1] create initial deposit
        Types.DepositVault memory fullVault = _depositLiquidityWithAssertions(
            toBeOverwrittendepositAmount,
            toBeOverwrittenExpectedSats,
            confirmationBlocks
        );

        console.log("calculating lock up period with confirmation blocks", confirmationBlocks);
        console.log("depositLockupPeriod", RiftUtils.calculateDepositLockupPeriod(confirmationBlocks));

        // [2] warp and withdraw to empty the vault
        vm.warp(block.timestamp + RiftUtils.calculateDepositLockupPeriod(confirmationBlocks));
        vm.recordLogs();
        exchange.withdrawLiquidity({vault: fullVault});
        Types.DepositVault memory emptyVault = _extractSingleVaultFromLogs(vm.getRecordedLogs());

        // [3] burn the USDC withdrawn from the vault
        mockToken.transfer(address(0), mockToken.balanceOf(address(this)));

        // [4] prepare for overwrite deposit
        mockToken.mint(address(this), depositAmount);
        mockToken.approve(address(exchange), depositAmount);

        // [5] generate fake tip block mmr proof
        Types.MMRProof memory mmr_proof = _generateFakeBlockMMRProofFFI(0);

        // [6] perform overwrite deposit
        vm.recordLogs();
        Types.DepositLiquidityWithOverwriteParams memory args = Types.DepositLiquidityWithOverwriteParams({
            depositParams: Types.DepositLiquidityParams({
                depositOwnerAddress: address(this),
                specifiedPayoutAddress: address(this),
                depositAmount: depositAmount,
                expectedSats: expectedSats,
                btcPayoutScriptPubKey: _generateBtcPayoutScriptPubKey(),
                depositSalt: depositSalt,
                confirmationBlocks: confirmationBlocks,
                safeBlockLeaf: mmr_proof.blockLeaf,
                safeBlockSiblings: mmr_proof.siblings,
                safeBlockPeaks: mmr_proof.peaks
            }),
            overwriteVault: emptyVault
        });

        exchange.depositLiquidityWithOverwrite(args);

        // [6] grab the logs, find the new vault
        Types.DepositVault memory overwrittenVault = _extractSingleVaultFromLogs(vm.getRecordedLogs());
        bytes32 commitment = exchange.getVaultCommitment(emptyVault.vaultIndex);

        // [7] verify "offchain" calculated commitment matches stored vault commitment
        bytes32 offchainCommitment = VaultLib.hashDepositVault(overwrittenVault);
        assertEq(offchainCommitment, commitment, "Offchain vault commitment should match");

        // [8] verify vault index remains the same
        assertEq(overwrittenVault.vaultIndex, emptyVault.vaultIndex, "Vault index should match original");

        // [9] verify caller has no balance left
        assertEq(mockToken.balanceOf(address(this)), 0, "Caller should have no balance left");

        // [10] verify owner address
        assertEq(overwrittenVault.ownerAddress, address(this), "Owner address should match");
    }

    function testFuzz_withdrawLiquidity(
        uint256 depositAmount,
        uint64 expectedSats,
        uint8 confirmationBlocks,
        uint256
    ) public {
        // [0] bound inputs
        depositAmount = bound(depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        expectedSats = uint64(bound(expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        confirmationBlocks = uint8(bound(confirmationBlocks, Constants.MIN_CONFIRMATION_BLOCKS, type(uint8).max));

        // [1] create initial deposit and get vault
        Types.DepositVault memory vault = _depositLiquidityWithAssertions(
            depositAmount,
            expectedSats,
            confirmationBlocks
        );
        uint256 initialBalance = mockToken.balanceOf(address(this));
        uint256 expectedWithdrawAmount = vault.depositAmount;

        // [2] warp to future time after lockup period
        vm.warp(block.timestamp + RiftUtils.calculateDepositLockupPeriod(confirmationBlocks) + 1);

        // [3] withdraw and capture updated vault from logs
        vm.recordLogs();
        exchange.withdrawLiquidity(vault);
        Types.DepositVault memory updatedVault = _extractSingleVaultFromLogs(vm.getRecordedLogs());

        // [4] verify updated vault commitment matches stored commitment
        bytes32 storedCommitment = exchange.getVaultCommitment(vault.vaultIndex);
        bytes32 calculatedCommitment = VaultLib.hashDepositVault(updatedVault);
        assertEq(calculatedCommitment, storedCommitment, "Vault commitment mismatch");

        // [5] verify vault is now empty
        assertEq(updatedVault.depositAmount, 0, "Updated vault should be empty");
        assertEq(updatedVault.vaultIndex, vault.vaultIndex, "Vault index should remain unchanged");

        // [6] verify tokens were transferred correctly
        assertEq(
            mockToken.balanceOf(address(this)),
            initialBalance + expectedWithdrawAmount,
            "Incorrect withdrawal amount"
        );
    }

    struct SubmitSwapProofParams {
        bytes32 swapBitcoinTxid;
        uint256 depositAmount;
        uint64 expectedSats;
        uint8 confirmationBlocks;
    }

    function testFuzz_submitSwapProof(SubmitSwapProofParams memory params, uint256) public {
        // [0] bound inputs
        params.depositAmount = bound(params.depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        params.expectedSats = uint64(bound(params.expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        params.confirmationBlocks = uint8(
            bound(params.confirmationBlocks, Constants.MIN_CONFIRMATION_BLOCKS, type(uint8).max)
        );

        // [1] create deposit vault
        Types.DepositVault memory vault = _depositLiquidityWithAssertions(
            params.depositAmount,
            params.expectedSats,
            params.confirmationBlocks
        );

        // [2] calculate correct swap totals from vault
        (uint256 totalSwapOutput, uint256 totalSwapFee) = VaultLib.calculateSwapTotals(vault);

        // [3] create dummy proof data
        (bytes memory proof, bytes memory compressedBlockLeaves) = _getMockProof();

        // [4] create dummy tip block data
        bytes32 priorMmrRoot = exchange.mmrRoot();

        (
            Types.MMRProof memory mmrProof,
            Types.MMRProof memory tipMmrProof
        ) = _generateFakeBlockWithConfirmationsMMRProofFFI(0, params.confirmationBlocks);
        /*
            SubmitSwapProofParams[] calldata swapParams,
            BlockProofParams calldata blockProofParams,
            Types.ProposedSwap[] calldata overwriteSwaps,
            bytes calldata proof
        */

        // [4] submit swap proof and capture logs
        vm.recordLogs();
        Types.SubmitSwapProofParams[] memory swapParams = new Types.SubmitSwapProofParams[](1);
        /*
        bytes32 swapBitcoinTxid;
        bytes32 swapBitcoinBlockHash;
        Types.DepositVault vault;
        StorageStrategy storageStrategy;
        uint16 localOverwriteIndex;
        */
        swapParams[0] = Types.SubmitSwapProofParams({
            swapBitcoinTxid: params.swapBitcoinTxid,
            vault: vault,
            storageStrategy: Types.StorageStrategy.Append,
            localOverwriteIndex: 0,
            swapBitcoinBlockLeaf: mmrProof.blockLeaf,
            swapBitcoinBlockSiblings: mmrProof.siblings,
            swapBitcoinBlockPeaks: mmrProof.peaks
        });

        /*
    struct BlockProofParams {
        bytes32 priorMmrRoot;
        bytes32 newMmrRoot;
        bytes compressedBlockLeaves;
        Types.BlockLeaf tipBlockLeaf;
        bytes32[] tipBlockSiblings;
        bytes32[] tipBlockPeaks;
*/

        Types.BlockProofParams memory blockProofParams = Types.BlockProofParams({
            priorMmrRoot: priorMmrRoot,
            newMmrRoot: mmrProof.mmrRoot,
            compressedBlockLeaves: compressedBlockLeaves,
            tipBlockLeaf: tipMmrProof.blockLeaf
        });
        console.log("blockProofParams.tipBlockLeaf.height", blockProofParams.tipBlockLeaf.height);
        Types.ProposedSwap[] memory overwriteSwaps = new Types.ProposedSwap[](0);

        exchange.submitBatchSwapProofWithLightClientUpdate(swapParams, blockProofParams, overwriteSwaps, proof);

        // [5] extract swap from logs
        Types.ProposedSwap memory createdSwap = _extractSingleSwapFromLogs(vm.getRecordedLogs());
        uint256 swapIndex = exchange.getSwapCommitmentsLength() - 1;
        bytes32 commitment = exchange.getSwapCommitment(swapIndex);

        // [6] verify swap details
        assertEq(createdSwap.swapIndex, swapIndex, "Swap index should match");
        assertEq(createdSwap.specifiedPayoutAddress, address(this), "Payout address should match");
        assertEq(createdSwap.totalSwapOutput, totalSwapOutput, "Swap amount should match");
        assertEq(createdSwap.totalSwapFee, totalSwapFee, "Swap fee should match");
        assertEq(uint8(createdSwap.state), uint8(Types.SwapState.Proved), "Swap should be in Proved state");

        // [7] verify commitment
        bytes32 offchainCommitment = VaultLib.hashSwap(createdSwap);
        assertEq(offchainCommitment, commitment, "Offchain swap commitment should match");
    }

    // Helper function to set up vaults and submit swap proof
    function _setupVaultsAndSubmitSwap(
        ReleaseLiquidityParams memory params
    )
        internal
        returns (
            Types.DepositVault memory vault,
            Types.ProposedSwap memory createdSwap,
            Types.MMRProof memory swapMmrProof,
            Types.MMRProof memory tipMmrProof
        )
    {
        // Create deposit vault
        vault = _depositLiquidityWithAssertions(params.depositAmount, params.expectedSats, params.confirmationBlocks);

        // [3] create dummy proof data
        (bytes memory proof, bytes memory compressedBlockLeaves) = _getMockProof();

        bytes32 priorMmrRoot = exchange.mmrRoot();
        (swapMmrProof, tipMmrProof) = _generateFakeBlockWithConfirmationsMMRProofFFI(1, params.confirmationBlocks);

        assertEq(swapMmrProof.mmrRoot, tipMmrProof.mmrRoot, "Mmr roots should match");

        vm.recordLogs();
        Types.SubmitSwapProofParams[] memory swapParams = new Types.SubmitSwapProofParams[](1);
        swapParams[0] = Types.SubmitSwapProofParams({
            swapBitcoinTxid: params.swapBitcoinTxid,
            vault: vault,
            storageStrategy: Types.StorageStrategy.Append,
            localOverwriteIndex: 0,
            swapBitcoinBlockLeaf: swapMmrProof.blockLeaf,
            swapBitcoinBlockSiblings: swapMmrProof.siblings,
            swapBitcoinBlockPeaks: swapMmrProof.peaks
        });
        Types.BlockProofParams memory blockProofParams = Types.BlockProofParams({
            priorMmrRoot: priorMmrRoot,
            newMmrRoot: tipMmrProof.mmrRoot,
            compressedBlockLeaves: compressedBlockLeaves,
            tipBlockLeaf: tipMmrProof.blockLeaf
        });
        Types.ProposedSwap[] memory overwriteSwaps = new Types.ProposedSwap[](0);

        exchange.submitBatchSwapProofWithLightClientUpdate(swapParams, blockProofParams, overwriteSwaps, proof);

        createdSwap = _extractSingleSwapFromLogs(vm.getRecordedLogs());
        return (vault, createdSwap, swapMmrProof, tipMmrProof);
    }

    // Helper function to verify balances and empty vaults
    function _verifyBalancesAndVaults(
        Types.DepositVault memory vault,
        uint256 initialBalance,
        uint256 initialFeeBalance,
        uint256 totalSwapOutput,
        uint256 totalSwapFee
    ) internal view {
        // Verify funds were transferred correctly
        assertEq(
            mockToken.balanceOf(address(this)),
            initialBalance + totalSwapOutput,
            "Incorrect amount transferred to recipient"
        );

        assertEq(
            exchange.accumulatedFeeBalance(),
            initialFeeBalance + totalSwapFee,
            "Incorrect fee amount accumulated"
        );

        // Verify vaults were emptied
        bytes32 vaultCommitment = exchange.getVaultCommitment(vault.vaultIndex);
        vault.depositAmount = 0;
        vault.depositFee = 0;
        bytes32 expectedCommitment = VaultLib.hashDepositVault(vault);
        assertEq(vaultCommitment, expectedCommitment, "Vault should be empty");
    }

    struct ReleaseLiquidityParams {
        bytes32 swapBitcoinTxid;
        uint256 depositAmount;
        uint64 expectedSats;
        uint8 confirmationBlocks;
    }

    function testFuzz_releaseLiquidity(ReleaseLiquidityParams memory params, uint256) public {
        // Bound inputs
        params.depositAmount = bound(params.depositAmount, Constants.MIN_DEPOSIT_AMOUNT, type(uint64).max);
        params.expectedSats = uint64(bound(params.expectedSats, Constants.MIN_OUTPUT_SATS, type(uint64).max));
        params.confirmationBlocks = uint8(
            bound(params.confirmationBlocks, Constants.MIN_CONFIRMATION_BLOCKS, type(uint8).max)
        );

        console.log("[0] setup vaults and submit swap");

        // Set up vaults and submit swap
        (
            Types.DepositVault memory vault,
            Types.ProposedSwap memory createdSwap,
            Types.MMRProof memory swapMmrProof,
            Types.MMRProof memory tipMmrProof
        ) = _setupVaultsAndSubmitSwap(params);

        // Record initial balances
        uint256 initialBalance = mockToken.balanceOf(address(this));
        uint256 initialFeeBalance = exchange.accumulatedFeeBalance();

        // validate the erc20 balance of the contract is equal to the amount sent params.depositAmount
        assertEq(
            mockToken.balanceOf(address(exchange)),
            params.depositAmount,
            "Contract should have the correct balance"
        );

        // total swap output + total swap fee should be equal to the deposited amount
        assertEq(
            params.depositAmount,
            createdSwap.totalSwapOutput + createdSwap.totalSwapFee,
            "Total swap output + total swap fee should be equal to the total amount deposited"
        );

        // Warp past challenge period
        vm.warp(block.timestamp + RiftUtils.calculateChallengePeriod(params.confirmationBlocks) + 2);

        // Release liquidity
        console.log("[1] release liquidity");
        vm.recordLogs();
        Types.ReleaseLiquidityParams memory releaseLiquidityParams = Types.ReleaseLiquidityParams({
            swap: createdSwap,
            bitcoinSwapBlockSiblings: swapMmrProof.siblings,
            bitcoinSwapBlockPeaks: swapMmrProof.peaks,
            utilizedVault: vault,
            tipBlockHeight: tipMmrProof.blockLeaf.height
        });

        Types.ReleaseLiquidityParams[] memory releaseLiquidityParamsArray = new Types.ReleaseLiquidityParams[](1);
        releaseLiquidityParamsArray[0] = releaseLiquidityParams;

        exchange.releaseLiquidityBatch(releaseLiquidityParamsArray);

        // Verify swap completion
        Types.ProposedSwap memory updatedSwap = _extractSingleSwapFromLogs(vm.getRecordedLogs());
        assertEq(uint8(updatedSwap.state), uint8(Types.SwapState.Finalized), "Swap should be finalized");

        // Verify balances and vaults
        _verifyBalancesAndVaults(
            vault,
            initialBalance,
            initialFeeBalance,
            updatedSwap.totalSwapOutput,
            updatedSwap.totalSwapFee
        );

        // Verify fee router balance and payout
        uint256 accountedFeeRouterBalancePrePayout = exchange.accumulatedFeeBalance();
        uint256 feeRouterBalancePrePayout = mockToken.balanceOf(address(exchange));

        console.log("accountedFeeRouterBalancePrePayout", accountedFeeRouterBalancePrePayout);
        console.log("feeRouterBalancePrePayout", feeRouterBalancePrePayout);

        assertEq(
            accountedFeeRouterBalancePrePayout,
            feeRouterBalancePrePayout - initialFeeBalance,
            "accounted fee balance should match the actual contract balance of USDC"
        );

        assertEq(
            feeRouterBalancePrePayout,
            updatedSwap.totalSwapFee,
            "Fee router should have an internal balance as a function of the swap amount"
        );

        exchange.payoutToFeeRouter();
        assertEq(
            mockToken.balanceOf(exchange.feeRouterAddress()),
            feeRouterBalancePrePayout,
            "Fee router should have received all fees"
        );
    }

    function test_specificFailcase() public {
        // Create swap
    }
}
