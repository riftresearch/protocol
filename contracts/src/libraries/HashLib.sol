// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {Types} from "./Types.sol";
import {Constants} from "./Constants.sol";
import {Errors} from "./Errors.sol";

import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

library HashLib {
    function hash(Types.DepositVault memory vault) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(vault));
    }

    function hash(Types.ProposedSwap memory swap) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(swap));
    }
}
