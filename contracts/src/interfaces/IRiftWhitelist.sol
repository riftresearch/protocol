// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRiftWhitelist {
    /// @notice Returns true if the account is whitelisted
    /// @param account The account to check
    /// @param authData The auth data to use for the whitelist check
    /// @return true if the account is whitelisted, false otherwise
    function isWhitelisted(address account, bytes memory authData) external view returns (bool);
}
