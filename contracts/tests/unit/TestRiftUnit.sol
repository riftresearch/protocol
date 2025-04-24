// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "../../src/interfaces/IRiftExchange.sol";
import {HelperTypes} from "../utils/HelperTypes.sol";
import {BitcoinLightClient} from "../../src/BitcoinLightClient.sol";
import {BitcoinScriptLib} from "../../src/libraries/BitcoinScriptLib.sol";
import {HashLib} from "../../src/libraries/HashLib.sol";
import {PeriodLib} from "../../src/libraries/PeriodLib.sol";
import {RiftExchange} from "../../src/RiftExchange.sol";
import {RiftTest} from "../utils/RiftTest.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";
import {FeeLib} from "../../src/libraries/FeeLib.sol";

import "forge-std/src/console.sol";

contract RiftExchangeUnitTest is RiftTest {
    using HashLib for DepositVault;
    using HashLib for ProposedSwap;
    using HashLib for BlockLeaf;

    // hacky way to get nice formatting for the vault in logs
    event VaultLog(DepositVault vault);
    event VaultCommitmentLog(bytes32 vaultCommitment);
    event LogVaults(DepositVault[] vaults);
    uint256 constant MAX_VAULTS = 2;

    // functional clone of validateDepositvaultHashes, but doesn't attempt to validate the vaults existence in storage
    // used to generate test data for circuits
    // TODO: directly call the rust api from here as part of fuzzer
    function generatedepositVaultHash(DepositVault[] memory vaults) internal pure returns (bytes32) {
        bytes32[] memory vaultHashes = new bytes32[](vaults.length);
        for (uint256 i = 0; i < vaults.length; i++) {
            vaultHashes[i] = vaults[i].hash();
        }
        return EfficientHashLib.hash(vaultHashes);
    }

    // use to generate test data for circuits
    // TODO: directly call the rust api from here as part of fuzzer
    function test_vaultHashes(DepositVault memory vault, uint256) public {
        // uint64 max here so it can be set easily in rust
        bound(vault.vaultIndex, 0, uint256(type(uint64).max));
        bytes32 vault_commitment = vault.hash();
        emit VaultLog(vault);
        emit VaultCommitmentLog(vault_commitment);
    }

    // used to generate test data for circuits
    // TODO: directly call the rust api from here as part of fuzzer
    function test_blockLeafHasher() public pure {
        BlockLeaf memory blockLeaf = BlockLeaf({
            blockHash: hex"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            height: 0,
            cumulativeChainwork: 4295032833
        });

        console.log("blockLeaf fields");
        console.logBytes32(blockLeaf.blockHash);
        console.logBytes32(bytes32(uint256(blockLeaf.height)));
        console.logBytes32(bytes32(blockLeaf.cumulativeChainwork));

        bytes32 blockLeafHash = blockLeaf.hash();
        console.log("blockLeafHash");
        console.logBytes32(blockLeafHash);
    }

    function constrainVault(
        DepositVault memory vault,
        uint64 maxValue
    ) internal pure returns (DepositVault memory) {
        return
            DepositVault({
                vaultIndex: vault.vaultIndex % maxValue,
                depositTimestamp: vault.depositTimestamp % maxValue,
                depositUnlockTimestamp: vault.depositUnlockTimestamp % maxValue,
                vaultAmount: vault.vaultAmount % maxValue,
                takerFee: vault.takerFee % maxValue,
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
    function test_aggregatevaultHashes(
        DepositVault[1] memory singleVaultSet,
        DepositVault[2] memory twoVaultSet,
        uint256
    ) public {
        uint64 maxValue = type(uint64).max;

        DepositVault[] memory singleVaultSetArray = new DepositVault[](1);
        singleVaultSetArray[0] = constrainVault(singleVaultSet[0], maxValue);
        bytes32 singleVaultCommitment = generatedepositVaultHash(singleVaultSetArray);
        emit LogVaults(singleVaultSetArray);
        emit VaultCommitmentLog(singleVaultCommitment);

        DepositVault[] memory twoVaultSetArray = new DepositVault[](2);
        twoVaultSetArray[0] = constrainVault(twoVaultSet[0], maxValue);
        twoVaultSetArray[1] = constrainVault(twoVaultSet[1], maxValue);
        bytes32 twoVaultCommitment = generatedepositVaultHash(twoVaultSetArray);
        emit LogVaults(twoVaultSetArray);
        emit VaultCommitmentLog(twoVaultCommitment);
    }

    // Test that depositLiquidity appends a new commitment to the vaultHashes array
    function testFuzz_depositLiquidity(
        uint256 depositAmount,
        uint64 expectedSats,
        uint8 confirmationBlocks,
        uint256
    ) public {
        // [0] bound deposit amount & expected sats
        depositAmount = bound(
            depositAmount,
            FeeLib.calculateMinDepositAmount(exchange.takerFeeBips()),
            type(uint64).max
        );
        expectedSats = uint64(bound(expectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max));
        confirmationBlocks = uint8(bound(confirmationBlocks, exchange.MIN_CONFIRMATION_BLOCKS(), type(uint8).max));
        _depositLiquidityWithAssertions(depositAmount, expectedSats, confirmationBlocks);
    }

    function testFuzz_withdrawLiquidity(
        uint256 depositAmount,
        uint64 expectedSats,
        uint8 confirmationBlocks,
        uint256
    ) public {
        // [0] bound inputs
        depositAmount = bound(
            depositAmount,
            FeeLib.calculateMinDepositAmount(exchange.takerFeeBips()),
            type(uint64).max
        );
        expectedSats = uint64(bound(expectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max));
        confirmationBlocks = uint8(bound(confirmationBlocks, exchange.MIN_CONFIRMATION_BLOCKS(), type(uint8).max));

        // [1] create initial deposit and get vault
        DepositVault memory vault = _depositLiquidityWithAssertions(
            depositAmount,
            expectedSats,
            confirmationBlocks
        );
        uint256 initialBalance = syntheticBTC.balanceOf(address(this));

        // [2] warp to future time after lockup period
        vm.warp(block.timestamp + PeriodLib.calculateDepositLockupPeriod(confirmationBlocks) + 1);

        // [3] withdraw and capture updated vault from logs
        vm.recordLogs();
        exchange.withdrawLiquidity(vault);
        DepositVault memory updatedVault = _extractSingleVaultFromLogs(vm.getRecordedLogs());

        // [4] verify updated vault commitment matches stored commitment
        bytes32 storedCommitment = exchange.vaultHashes(vault.vaultIndex);
        bytes32 calculatedCommitment = updatedVault.hash();
        assertEq(calculatedCommitment, storedCommitment, "Vault commitment mismatch");

        // [5] verify vault is now empty
        assertEq(updatedVault.vaultAmount, 0, "Updated vault should be empty");
        assertEq(updatedVault.vaultIndex, vault.vaultIndex, "Vault index should remain unchanged");

        // [6] verify tokens were transferred correctly
        assertEq(syntheticBTC.balanceOf(address(this)), initialBalance + depositAmount, "Incorrect withdrawal amount");
    }

    function testFuzz_submitSwapProof(SubmitSwapProofParams memory params, uint256) public {
        // [0] bound inputs
        params.vault.vaultAmount = bound(
            params.vault.vaultAmount,
            FeeLib.calculateMinDepositAmount(exchange.takerFeeBips()),
            type(uint64).max
        );
        params.vault.expectedSats = uint64(bound(params.vault.expectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max));
        params.vault.confirmationBlocks = uint8(
            bound(params.vault.confirmationBlocks, exchange.MIN_CONFIRMATION_BLOCKS(), type(uint8).max)
        );

        // [1] create deposit vault
        DepositVault memory vault = _depositLiquidityWithAssertions(
            params.vault.vaultAmount,
            params.vault.expectedSats,
            params.vault.confirmationBlocks
        );

        // [3] create dummy proof data
        (bytes memory proof, bytes memory compressedBlockLeaves) = _getMockProof();

        // [4] create dummy tip block data
        bytes32 priorMmrRoot = exchange.mmrRoot();

        (
            HelperTypes.MMRProof memory mmrProof,
            HelperTypes.MMRProof memory tipMmrProof
        ) = _generateFakeBlockWithConfirmationsMMRProofFFI(0, params.vault.confirmationBlocks);
        /*
            SubmitSwapProofParams[] calldata swapParams,
            BlockProofParams calldata blockProofParams,
            bytes calldata proof
        */

        // [4] submit swap proof and capture logs
        vm.recordLogs();
        SubmitSwapProofParams[] memory swapParams = new SubmitSwapProofParams[](1);

        swapParams[0] = SubmitSwapProofParams({
            swapBitcoinTxid: params.swapBitcoinTxid,
            vault: vault,
            swapBitcoinBlockLeaf: mmrProof.blockLeaf,
            swapBitcoinBlockSiblings: mmrProof.siblings,
            swapBitcoinBlockPeaks: mmrProof.peaks
        });


        BlockProofParams memory blockProofParams = BlockProofParams({
            priorMmrRoot: priorMmrRoot,
            newMmrRoot: mmrProof.mmrRoot,
            compressedBlockLeaves: compressedBlockLeaves,
            tipBlockLeaf: tipMmrProof.blockLeaf
        });
        console.log("blockProofParams.tipBlockLeaf.height", blockProofParams.tipBlockLeaf.height);

        exchange.submitBatchSwapProofWithLightClientUpdate(swapParams, blockProofParams, proof);

        // [5] extract swap from logs
        ProposedSwap memory createdSwap = _extractSingleSwapFromLogs(vm.getRecordedLogs());
        uint256 swapIndex = exchange.getSwapHashesLength() - 1;
        bytes32 hash = exchange.swapHashes(swapIndex);

        uint256 takerFee = FeeLib.calculateFeeFromDeposit(params.vault.vaultAmount, exchange.takerFeeBips());

        // [6] verify swap details
        assertEq(createdSwap.swapIndex, swapIndex, "Swap index should match");
        assertEq(createdSwap.specifiedPayoutAddress, address(this), "Payout address should match");
        assertEq(createdSwap.totalSwapOutput, params.vault.vaultAmount - takerFee, "Swap amount should match");
        assertEq(createdSwap.takerFee, takerFee, "Swap fee should match");
        assertEq(uint8(createdSwap.state), uint8(SwapState.Proved), "Swap should be in Proved state");

        // [7] verify hash
        bytes32 offchainHash = createdSwap.hash();
        assertEq(offchainHash, hash, "Offchain swap hash should match");
    }

    struct FuzzReleaseLiquidityParams {
        bytes32 swapBitcoinTxid;
        uint256 depositAmount;
        uint64 expectedSats;
        uint8 confirmationBlocks;
    }

    // Helper function to set up vaults and submit swap proof
    function _setupVaultsAndSubmitSwap(
        FuzzReleaseLiquidityParams memory params
    )
        internal
        returns (
            DepositVault memory vault,
            ProposedSwap memory createdSwap,
            HelperTypes.MMRProof memory swapMmrProof,
            HelperTypes.MMRProof memory tipMmrProof
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
        SubmitSwapProofParams[] memory swapParams = new SubmitSwapProofParams[](1);
        swapParams[0] = SubmitSwapProofParams({
            swapBitcoinTxid: params.swapBitcoinTxid,
            vault: vault,
            swapBitcoinBlockLeaf: swapMmrProof.blockLeaf,
            swapBitcoinBlockSiblings: swapMmrProof.siblings,
            swapBitcoinBlockPeaks: swapMmrProof.peaks
        });
        BlockProofParams memory blockProofParams = BlockProofParams({
            priorMmrRoot: priorMmrRoot,
            newMmrRoot: tipMmrProof.mmrRoot,
            compressedBlockLeaves: compressedBlockLeaves,
            tipBlockLeaf: tipMmrProof.blockLeaf
        });

        exchange.submitBatchSwapProofWithLightClientUpdate(swapParams, blockProofParams, proof);

        createdSwap = _extractSingleSwapFromLogs(vm.getRecordedLogs());
        return (vault, createdSwap, swapMmrProof, tipMmrProof);
    }

    // Helper function to verify balances and empty vaults
    function _verifyBalancesAndVaults(
        DepositVault memory vault,
        uint256 initialBalance,
        uint256 initialFeeBalance,
        uint256 totalSwapOutput,
        uint256 totalSwapFee
    ) internal view {
        // Verify funds were transferred correctly
        assertEq(
            syntheticBTC.balanceOf(address(this)),
            initialBalance + totalSwapOutput,
            "Incorrect amount transferred to recipient"
        );

        assertEq(
            exchange.accumulatedFeeBalance(),
            initialFeeBalance + totalSwapFee,
            "Incorrect fee amount accumulated"
        );

        // Verify vaults were emptied
        bytes32 vaultCommitment = exchange.vaultHashes(vault.vaultIndex);
        vault.vaultAmount = 0;
        vault.takerFee = 0;
        bytes32 expectedCommitment = vault.hash();
        assertEq(vaultCommitment, expectedCommitment, "Vault should be empty");
    }

 function testFuzz_releaseLiquidity(FuzzReleaseLiquidityParams memory params, uint256) public {
        // Bound inputs
        params.depositAmount = bound(params.depositAmount, FeeLib.calculateMinDepositAmount(exchange.takerFeeBips()), type(uint64).max);
        params.expectedSats = uint64(bound(params.expectedSats, exchange.MIN_OUTPUT_SATS(), type(uint64).max));
        params.confirmationBlocks = uint8(
            bound(params.confirmationBlocks, exchange.MIN_CONFIRMATION_BLOCKS(), type(uint8).max)
        );

        console.log("[0] setup vaults and submit swap");

        // Set up vaults and submit swap
        (
            DepositVault memory vault,
            ProposedSwap memory createdSwap,
            HelperTypes.MMRProof memory swapMmrProof,
            HelperTypes.MMRProof memory tipMmrProof
        ) = _setupVaultsAndSubmitSwap(params);

        // Record initial balances
        uint256 initialBalance = syntheticBTC.balanceOf(address(this));
        uint256 initialFeeBalance = exchange.accumulatedFeeBalance();

        // validate the erc20 balance of the contract is equal to the amount sent params.depositAmount
        assertEq(
            syntheticBTC.balanceOf(address(exchange)),
            params.depositAmount,
            "Contract should have the correct balance"
        );

        // total swap output + total swap fee should be equal to the deposited amount
        assertEq(
            params.depositAmount,
            createdSwap.totalSwapOutput + createdSwap.takerFee,
            "Total swap output + total swap fee should be equal to the total amount deposited"
        );

        // Warp past challenge period
        vm.warp(block.timestamp + PeriodLib.calculateChallengePeriod(params.confirmationBlocks) + 2);

        // Release liquidity
        console.log("[1] release liquidity");
        vm.recordLogs();
        ReleaseLiquidityParams memory releaseLiquidityParams = ReleaseLiquidityParams({
            swap: createdSwap,
            bitcoinSwapBlockSiblings: swapMmrProof.siblings,
            bitcoinSwapBlockPeaks: swapMmrProof.peaks,
            utilizedVault: vault,
            tipBlockHeight: tipMmrProof.blockLeaf.height
        });

        ReleaseLiquidityParams[] memory releaseLiquidityParamsArray = new ReleaseLiquidityParams[](1);
        releaseLiquidityParamsArray[0] = releaseLiquidityParams;

        exchange.releaseLiquidityBatch(releaseLiquidityParamsArray);

        // Verify swap completion
        ProposedSwap memory updatedSwap = _extractSingleSwapFromLogs(vm.getRecordedLogs());
        assertEq(uint8(updatedSwap.state), uint8(SwapState.Finalized), "Swap should be finalized");

        // Verify balances and vaults
        _verifyBalancesAndVaults(
            vault,
            initialBalance,
            initialFeeBalance,
            updatedSwap.totalSwapOutput,
            updatedSwap.takerFee
        );

        // Verify fee router balance and payout
        uint256 accountedFeeRouterBalancePrePayout = exchange.accumulatedFeeBalance();
        uint256 feeRouterBalancePrePayout = syntheticBTC.balanceOf(address(exchange));

        console.log("accountedFeeRouterBalancePrePayout", accountedFeeRouterBalancePrePayout);
        console.log("feeRouterBalancePrePayout", feeRouterBalancePrePayout);

        assertEq(
            accountedFeeRouterBalancePrePayout,
            feeRouterBalancePrePayout - initialFeeBalance,
            "accounted fee balance should match the actual contract balance of USDC"
        );

        assertEq(
            feeRouterBalancePrePayout,
            updatedSwap.takerFee,
            "Fee router should have an internal balance as a function of the swap amount"
        );

        exchange.payoutToFeeRouter();
        assertEq(
            syntheticBTC.balanceOf(exchange.feeRouterAddress()),
            feeRouterBalancePrePayout,
            "Fee router should have received all fees"
        );
    }
}
