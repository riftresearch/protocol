// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.0;

import {ERC20} from "solady/src/tokens/ERC20.sol";

// Mock Token contract (with interop with the canonical cbBTC contract)
contract MockToken is ERC20 {
    string public $name;
    string public $symbol;
    uint8 public $decimals;

    function name() public view virtual override returns (string memory) {
        return $name;
    }

    /// @dev Returns the symbol of the token.
    function symbol() public view virtual override returns (string memory) {
        return $symbol;
    }

    /// @dev Returns the decimals places of the token.
    function decimals() public view virtual override returns (uint8) {
        return $decimals;
    }

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        $name = _name;
        $symbol = _symbol;
        $decimals = _decimals;
    }

    function mint(address _to, uint256 _amount) public {
        _mint(_to, _amount);
    }

    // Interop with cbBTC
    function masterMinter() external view returns (address) {
        return msg.sender;
    }

    // Interop with cbBTC
    function configureMinter(address /*minter*/, uint256 /*minterAllowedAmount*/) external pure returns (bool) {
        return true;
    }
}
