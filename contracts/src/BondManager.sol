// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {Types} from "./libraries/Types.sol";

/**
 * @title Bond Manager Core Logic
 * @notice Provides the core abstract logic for managing market maker collateral (bonds).
 * @dev Handles the lifecycle of bonds: depositing, withdrawing, locking for orders, unlocking upon completion,
 *  and slashing upon failure. Calculates required bond amounts based on order size and duration using `BOND_APY_BIPS`.
 *  Calculates and distributes slashed bond portions (to user and protocol fee recipient) using `PROTOCOL_BOND_FEE_BIPS`.
 *  Concrete implementations must provide the actual token transfer mechanisms by overriding `_transfer` and `_transferFrom`.
 */
abstract contract BondManager {
    // the APY the filler (mm) must pay the protocol + depositor (user) if they
    // don't fill the order
    uint32 constant BOND_APY_BIPS = 100e2; // 100%

    // Percentage of a bond the protocol keeps as a fee if an order isn't filled
    uint32 constant PROTOCOL_BOND_FEE_BIPS = 5e2; // 5%

    // Precomputed denominator for interest calculations
    uint256 constant INTEREST_DENOMINATOR = 315_360_000_000; // 10_000 * secondsPerYear

    // market maker => total available bond
    mapping(address => uint256) public bonds;

    // bond id => Bond
    mapping(bytes32 => Types.ActiveBond) public activeBonds;

    // Child contract implements the following so we can transfer tokens
    function _transfer(address to, uint256 amount) internal virtual;

    function _transferFrom(address from, address to, uint256 amount) internal virtual;

    // Deposit bond from caller into their bond mapping
    function _depositBond(uint256 amount) internal {
        bonds[msg.sender] += amount;
        _transferFrom(msg.sender, address(this), amount);
    }

    // Withdraw bond from caller's bond mapping
    function _withdrawBond(uint256 amount) internal {
        bonds[msg.sender] -= amount;
        _transfer(msg.sender, amount);
    }

    // 1. Validate caller has sufficient bond in their mapping
    // 2. Subtract _computeBond() from their mapping
    // 3. Create an ActiveBond by bond id and msg.sender
    function _lockBond(bytes32 bondId, uint256 amount, uint32 duration) internal {
        uint256 bond = _computeBond(amount, duration);
        bonds[msg.sender] -= bond;
        activeBonds[bondId] = Types.ActiveBond({marketMaker: msg.sender, bondAmount: uint96(bond)});
    }

    // Bond is returned in full to the maker maker's bond account
    function _unlockBond(bytes32 bondId) internal {
        Types.ActiveBond memory activeBond = activeBonds[bondId];
        bonds[activeBond.marketMaker] += activeBond.bondAmount;
        delete activeBonds[bondId];
    }

    //  Calculates protocol bond and user bond using `PROTOCOL_BOND_FEE_BIPS`
    function _slashBond(bytes32 bondId, address user, address protocolBondFeeRecipient) internal {
        Types.ActiveBond memory activeBond = activeBonds[bondId];
        uint256 protocolBondFee = (activeBond.bondAmount * PROTOCOL_BOND_FEE_BIPS) / 1e4;
        uint256 userBond = activeBond.bondAmount - protocolBondFee;
        delete activeBonds[bondId];
        // we're okay with the protocol bond fee being 0 if the order is small
        if (protocolBondFee > 0) {
            _transfer(protocolBondFeeRecipient, protocolBondFee);
        }
        _transfer(user, userBond);
    }

    /**
     * @notice Calculates the required bond amount based on a principal amount and lockup duration.
     * @dev Computes a penalty amount using simple interest (`BOND_APY_BIPS`) over the specified `duration` (in seconds).
     * minimum bond amount is 1, guaranteed by the ceil-div
     * @param amount The principal amount used as the basis for the bond calculation.
     * @param duration The lockup period in seconds for which the bond is required.
     * @return bondAmount The calculated bond amount required for the given parameters.
     */
    function _computeBond(uint256 amount, uint32 duration) private pure returns (uint256 bondAmount) {
        uint256 num = amount * BOND_APY_BIPS * duration;
        bondAmount = (num + INTEREST_DENOMINATOR - 1) / INTEREST_DENOMINATOR;
    }
}
