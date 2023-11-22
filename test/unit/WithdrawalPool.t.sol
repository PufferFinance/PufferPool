// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { Permit } from "puffer/struct/Permit.sol";
import { TestHelper } from "../helpers/TestHelper.sol";

contract WithdrawalPoolTest is TestHelper {
    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();
    }

    // Test withdraw ETH if there is neough liquidity
    function testWithdrawETH() public {
        address bob = makeAddr("bob");

        vm.deal(address(withdrawalPool), 100 ether);
        vm.deal(bob, 10 ether);

        address charlie = makeAddr("charlie");

        assertTrue(charlie.balance == 0, "charlie should be poor");

        vm.startPrank(bob);
        pool.depositETH{ value: 10 ether }();

        pool.approve(address(withdrawalPool), type(uint256).max);
        withdrawalPool.withdrawETH(charlie, 1 ether);

        assertTrue(charlie.balance != 0, "charlie got ETH");
    }

    // Depositor deposits and gives his signature so the withdrawer can take that signature and submit it to get the ETH
    function testWithdrawETHWithSignature() public {
        vm.deal(address(withdrawalPool), 1000 ether);

        string memory addressSeed = "pufETHDepositor";
        address pufETHDepositor = makeAddr(addressSeed);

        _TestTemps memory temp = _testTemps(addressSeed, address(withdrawalPool), 50 ether, block.timestamp);

        Permit memory permit = _signPermit(temp);

        vm.deal(pufETHDepositor, 1000 ether);

        address charlie = makeAddr("charlie");

        assertTrue(charlie.balance == 0, "charlie should be poor");

        vm.prank(pufETHDepositor);
        pool.depositETH{ value: 1000 ether }();

        withdrawalPool.withdrawETH(charlie, permit);

        assertTrue(charlie.balance != 0, "charlie got ETH");
    }
}
