// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

import {ERC20} from "solady/src/tokens/ERC20.sol";

// Mock Token contract (with interop with the canonical cbBTC contract)
contract TokenizedBTC is ERC20 {
    function name() public view virtual override returns (string memory) {
        return "Tokenized BTC";
    }

    /// @dev Returns the symbol of the token.
    function symbol() public view virtual override returns (string memory) {
        return "sBTC";
    }

    /// @dev Returns the decimals places of the token.
    function decimals() public view virtual override returns (uint8) {
        return 8;
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
