// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { TestBase } from "../TestBase.t.sol";
import { BeaconMock } from "../mocks/BeaconMock.sol";
import { console } from "forge-std/console.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";

contract PufferPoolTest is TestHelper, TestBase {
    using ECDSA for bytes32;

    event DepositRateChanged(uint256 oldValue, uint256 newValue);
    event ETHProvisioned(address eigenPodProxy, bytes blsPubKey, uint256 timestamp);

    address rewardsRecipient = makeAddr("rewardsRecipient");

    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();
    }

    // Test setup
    function testSetup() public {
        assertEq(pool.name(), "Puffer ETH");
        assertEq(pool.symbol(), "pufETH");
        assertEq(pool.getPufETHtoETHExchangeRate(), FixedPointMathLib.WAD);
    }

    // Fuzz test for depositing ETH to PufferPool
    function testDeposit(address depositor, uint256 depositAmount) public fuzzedAddress(depositor) {
        depositAmount = bound(depositAmount, 0.01 ether, 1_000_000 ether);

        vm.deal(depositor, depositAmount);

        uint256 expectedAmount = pool.calculateETHToPufETHAmount(depositAmount);

        vm.startPrank(depositor);
        assertEq(pool.balanceOf(depositor), 0, "recipient pufETH amount before deposit");

        uint256 minted = pool.depositETH{ value: depositAmount }();
        vm.stopPrank();

        uint256 expectedETH = pool.calculatePufETHtoETHAmount(minted);
        assertEq(expectedETH, minted, "amounts should match 1:1 ratio");

        assertEq(pool.balanceOf(depositor), depositAmount, "recipient pufETH amount");
        assertEq(expectedAmount, depositAmount, "recipient pufETH calculated amount");
    }

    // Test Alice and Bob depositing
    function testMultipleDeposits() public {
        address bob = makeAddr("bob");
        address alice = makeAddr("alice");

        vm.deal(bob, 100 ether);
        vm.deal(alice, 100 ether);

        vm.startPrank(bob);
        (bool success,) = address(pool).call{ value: 10 ether }("");

        assertTrue(success, "failed");
        assertEq(pool.balanceOf(bob), 10 ether, "bob balance");

        vm.startPrank(alice);

        uint256 minted = pool.depositETH{ value: 10 ether }();

        assertEq(minted, 10 ether, "amounts dont match");
        assertEq(pool.balanceOf(alice), 10 ether, "alice balance");
    }

    // Create validator with Mock beacon chain deposit contract
    function testCreateValidator() public {
        BeaconMock mock = new BeaconMock();

        vm.deal(address(pool), 32 ether);
        vm.etch(address(pool.BEACON_DEPOSIT_CONTRACT()), address(mock).code);

        vm.startPrank(address(pufferProtocol));
        pool.createValidator("", "", "", "");
    }

    // Test burning of pufETH
    function testBurn(address depositor) public fuzzedAddress(depositor) {
        uint256 amount = 5 ether;
        vm.deal(depositor, amount);

        vm.startPrank(depositor);
        uint256 pufETHAmount = pool.depositETH{ value: amount }();
        assertTrue(pufETHAmount != 0, "invalid pufETH amount");

        pool.burn(pufETHAmount);

        assertTrue(0 == pool.balanceOf(depositor));
    }

    // Deposit should revert when trying to deposit too small amount
    function testDepositRevertsForTooSmallAmount() public {
        vm.expectRevert(IPufferPool.InsufficientETH.selector);
        pool.depositETH{ value: 0.005 ether }();
    }

    function testRatioChange() public {
        // total supply 0 means ratio is 1:1
        uint256 minted = pool.depositETH{ value: 1 ether }();
        assertEq(minted, 1 ether, "minted amount");

        // Simulate rewards of 1 ETH
        pool.depositETHWithoutMinting{ value: 1 ether }();

        // Fast forward 1801 blocks ~ 6 hours
        vm.roll(1801);

        vm.prank(address(guardiansSafe));
        pufferProtocol.updateBacking({ ethAmount: 2 ether, lockedETH: 0, pufETHTotalSupply: 1 ether, blockNumber: 1 });

        // total supply is 1
        // total eth = 2
        // ratio is 1/2 = 0.5, mint 0.5 pufETH to caller

        minted = pool.depositETH{ value: 1 ether }();

        assertEq(minted, 0.5 ether, "ratio didn't change");
    }

    function testRatioChangeSandwichAttack(uint256 numberOfValidators, uint256 attackerAmount) public {
        numberOfValidators = bound(numberOfValidators, 10, 1000);

        attackerAmount = bound(attackerAmount, 1 ether, 100 ether);
        address attacker = makeAddr("attacker");

        vm.deal(attacker, attackerAmount);

        uint256 startAmountInTheSystem = numberOfValidators * 32 ether;
        // Imagine that we have 50 validators = 1600 ETH
        // Daily reward amount ~ 50 * 0.00237 ETH => 0.1185 ETH
        vm.deal(address(withdrawalPool), startAmountInTheSystem);

        // total supply 0 means ratio is 1:1
        uint256 gasBefore = gasleft();
        uint256 minted = pool.depositETH{ value: 10 ether }();
        uint256 gasAfter = gasleft();
        assertEq(minted, 10 ether, "minted amount");

        uint256 GWEI = 1000000000;
        uint256 gasConsumedForDeposit = (gasBefore - gasAfter) * GWEI; // gas * gwei to get ETH amount;

        // Say that we got 10 ETH in rewards today

        vm.startPrank(attacker);
        uint256 attackerMinted = pool.depositETH{ value: attackerAmount }();
        pool.approve(address(withdrawalPool), type(uint256).max);
        vm.stopPrank();

        uint256 averageDailyRewradAmount = 0.00237 ether;

        // Change withdrawal pool amount to start amount + daily rewards
        vm.deal(address(withdrawalPool), startAmountInTheSystem + (numberOfValidators * averageDailyRewradAmount));

        vm.startPrank(attacker);
        gasBefore = gasleft();
        withdrawalPool.withdrawETH(attacker, attackerMinted);
        gasAfter = gasleft();
        vm.stopPrank();

        uint256 gasConsumedForWithdrawal = (gasBefore - gasAfter) * GWEI; // gas * gwei to get ETH amount;

        assertTrue(
            attacker.balance < (attackerAmount - (gasConsumedForWithdrawal + gasConsumedForDeposit)),
            "attacker is in profit"
        );
        // assertApproxEqRel(attacker.balance, 10 ether, 1e16, "balance is bad"); // diff 1%
    }

    function testStorageS() public {
        PufferProtocolStorage.PufferPoolStorage memory data = pufferProtocol.getPuferPoolStorage();
        assertEq(data.lastUpdate, 0, "last update");
    }
}
