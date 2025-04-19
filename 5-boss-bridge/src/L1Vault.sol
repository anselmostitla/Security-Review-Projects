// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

/// @title L1Vault
/// @author Boss Bridge Peeps
/// @notice This contract is responsible for locking & unlocking tokens on the L1 or L2
/// @notice It will approve the bridge to move money in and out of this contract
/// @notice It's owner should be the bridge
contract L1Vault is Ownable {
    // @audit-info should be immutable! 
    IERC20 public token;

    constructor(IERC20 _token) Ownable(msg.sender) {
        token = _token;
    }

    // @audit missing output check, use safeERC20 (unchecked return)
    function approveTo(address target, uint256 amount) external onlyOwner {
        // q will this be a vulnerability?, once approve, target can manage the tokens
        // @audit-info unchecked result, it should return a true value if not approve is not guaranty
        token.approve(target, amount);
        // require allowance(msg.sender, target) >= amount greater or equal than amount
    }
}
