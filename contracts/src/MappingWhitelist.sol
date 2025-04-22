// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {Ownable} from "solady/src/auth/Ownable.sol";

import {IRiftWhitelist} from "./interfaces/IRiftWhitelist.sol";

contract MappingWhitelist is IRiftWhitelist, Ownable {
    event WhitelistUpdated(address indexed account, bool isWhitelisted);
    mapping(address => bool) public whitelist;

    constructor() {
        _initializeOwner(msg.sender);
    }

    function isWhitelisted(address account, bytes memory) external view returns (bool) {
        return whitelist[account];
    }

    function addToWhitelist(address account) external onlyOwner {
        whitelist[account] = true;
        emit WhitelistUpdated(account, true);
    }

    function removeFromWhitelist(address account) external onlyOwner {
        whitelist[account] = false;
        emit WhitelistUpdated(account, false);
    }
}