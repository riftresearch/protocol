// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.0;

import {ERC20} from "solmate/src/tokens/ERC20.sol";

// Mock Token contract (with interop with the canonical cbBTC contract)
contract MockToken is ERC20 {
    constructor(string memory name, string memory symbol, uint8 decimals) ERC20(name, symbol, decimals) {}

    function mint(address _to, uint256 _amount) public {
        _mint(_to, _amount);
    }

    // Interop
    function masterMinter() public view returns (address) {
        return msg.sender;
    }

    // Interop
    function configureMinter(address minter, uint256 minterAllowedAmount) external returns (bool) {
        return true;
    }
}
