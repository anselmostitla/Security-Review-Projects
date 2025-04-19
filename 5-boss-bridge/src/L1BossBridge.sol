// __| |_____________________________________________________| |__
// __   _____________________________________________________   __
//   | |                                                     | |
//   | | ____                  ____       _     _            | |
//   | || __ )  ___  ___ ___  | __ ) _ __(_) __| | __ _  ___ | |
//   | ||  _ \ / _ \/ __/ __| |  _ \| '__| |/ _` |/ _` |/ _ \| |
//   | || |_) | (_) \__ \__ \ | |_) | |  | | (_| | (_| |  __/| |
//   | ||____/ \___/|___/___/ |____/|_|  |_|\__,_|\__, |\___|| |
//   | |                                          |___/      | |
// __| |_____________________________________________________| |__
// __   _____________________________________________________   __
//   | |                                                     | |

// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import { L1Vault } from "./L1Vault.sol";

contract L1BossBridge is Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // @audit-info should be constant!
    uint256 public DEPOSIT_LIMIT = 100_000 ether;

    IERC20 public immutable token;
    L1Vault public immutable vault;
    mapping(address account => bool isSigner) public signers;
    
    // // new code
    // mapping(address user => uint256 depositedAmount) public deposits;

    error L1BossBridge__DepositLimitReached();
    error L1BossBridge__Unauthorized();
    error L1BossBridge__CallFailed();

    event Deposit(address from, address to, uint256 amount);

    constructor(IERC20 _token) Ownable(msg.sender) {
        token = _token;
        vault = new L1Vault(token);
        // Allows the bridge to move tokens out of the vault to facilitate withdrawals
        vault.approveTo(address(this), type(uint256).max);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function setSigner(address account, bool enabled) external onlyOwner {
        // @audit require(account != address(0))
        // @audit require(signers[account] = !enabled;)
        signers[account] = enabled;
    }

    /*
     * @notice Locks tokens in the vault and emits a Deposit event
     * the unlock event will trigger the L2 minting process. There are nodes listening
     * for this event and will mint the corresponding tokens on L2. This is a centralized process.
     * 
     * @param from The address of the user who is depositing tokens
     * @param l2Recipient The address of the user who will receive the tokens on L2
     * @param amount The amount of tokens to deposit
     */
    // @audit Impact high, likelihood: high, 
    // if alice approves the bridge, any other user can steal their funcds
    function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
        // @audit inputs validations
        // if amount > 0 saves gas for the user
        if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
            revert L1BossBridge__DepositLimitReached();
        }
        
        // audit keep track of deposit tokens of msg.sender for example using a mapping: deposits[token][msg.sender] += amount;
        
        // // new code
        // deposits[msg.sender] += amount; 

        token.safeTransferFrom(from, address(vault), amount);

        // Our off-chain service picks up this event and mints the corresponding tokens on L2
        // @audit-info should follow CEI
        emit Deposit(from, l2Recipient, amount);
    }

    /*
     * @notice This is the function responsible for withdrawing tokens from L2 to L1.
     * Our L2 will have a similar mechanism for withdrawing tokens from L1 to L2.
     * @notice The signature is required to prevent replay attacks. 
     * 
     * @param to The address of the user who will receive the tokens on L1
     * @param amount The amount of tokens to withdraw
     * @param v The v value of the signature
     * @param r The r value of the signature
     * @param s The s value of the signature
     */
    function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        // @audit require(to != address(0)) to avoid burning tokens accidentally;
        // @audit require(msg.sender == to);
        sendToL1(
            v,
            r,
            s,
            abi.encode(
                address(token),
                0, // value
                abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount))
            )
        );
    }

    /*
     * @notice This is the function responsible for withdrawing ETH from L2 to L1.
     *
     * @param v The v value of the signature
     * @param r The r value of the signature
     * @param s The s value of the signature
     * @param message The message/data to be sent to L1 (can be blank)
     */
    // @audit make this function internal
    function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s);

        // @audit q we need a mechanism like a mapping to mark a (v,r,s) as used so that nobody can used again
        if (!signers[signer]) {
            revert L1BossBridge__Unauthorized();
        }


        (address target, uint256 value, bytes memory data) = abi.decode(message, (address, uint256, bytes));

        // // new code
        // (, address to, uint256 amount) = decodeTransferFrom(data);
        // require(deposits[to] >= amount);
        // deposits[msg.sender] -= amount; 

        // @audit-gas data with crazy gas cost
        (bool success,) = target.call{ value: value }(data);
        if (!success) {
            revert L1BossBridge__CallFailed();
        }
    }

    function decodeTransferFrom(bytes memory callData) public pure returns (
        address from,
        address to,
        uint256 amount
    ) {
        // Copy everything except the first 4 bytes (selector)
        bytes memory args = new bytes(callData.length - 4);
        for (uint256 i = 0; i < args.length; ++i) {
            args[i] = callData[i + 4];
        }

        return abi.decode(args, (address, address, uint256));
    }
}
