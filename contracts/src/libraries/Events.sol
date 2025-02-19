// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;
import {Types} from "./Types.sol";

library Events {
    event BitcoinLightClientUpdated(bytes32 priorMmrRoot, bytes32 newMmrRoot, bytes compressedBlockLeaves);
    event VaultsUpdated(Types.DepositVault[] vaults, Types.VaultUpdateContext context);
    event SwapsUpdated(Types.ProposedSwap[] swaps, Types.SwapUpdateContext context);
}
