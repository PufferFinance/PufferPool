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

        vm.startPrank(address(serviceManager));
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
}
