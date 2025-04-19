// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

/* 
* @title TokenFactory
* @dev Allows the owner to deploy new ERC20 contracts
* @dev This contract will be deployed on both an L1 & an L2
*/
contract TokenFactory is Ownable {
    mapping(string tokenSymbol => address tokenAddress) private s_tokenToAddress; // addressOfSymbol symbolToAddress

    event TokenDeployed(string symbol, address addr);

    constructor() Ownable(msg.sender) { }

    /*
     * @dev Deploys a new ERC20 contract
     * @param symbol The symbol of the new token
     * @param contractBytecode The bytecode of the new token
     */
    function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
        // audit input validations
        // require(bytes(symbol)>0)
        // require(s_tokenToAddress[symbol] == address(0))
        // require(bytes(contractBytecode)>0)
        assembly {
            // @audit-high this won't work on ZKSync!!
            // https://docs.zksync.io/zksync-protocol/differences/evm-instructions?utm_source=chatgpt.com
            // Test this on zksync
            addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode)) 
            // e add(contractBytecode, 0x20): get the memory address of contractBytecode, remember the first part contains the length so we need to skip or add 0x20, that is, we skip the first 32 bytes, this is where our contractBytecode really beggins
            // e mload(contractBytecode) reads the first 32 bytes of contractBytecode, but in those first 32 bytes is located the length, that is the size 
        }
        // audit unchecked that addr is not address zero
        // require(addr != address(0));
        s_tokenToAddress[symbol] = addr; // e symbolToaddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
    }

    function getTokenAddressFromSymbol(string memory symbol) public view returns (address addr) {
        return s_tokenToAddress[symbol];
    }
}
