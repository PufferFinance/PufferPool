// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferPoolStorage } from "puffer/struct/PufferPoolStorage.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";

contract Mock is ERC20 {
    constructor() ERC20("mock", "mock") {
        _mint(msg.sender, 1_000_000 ether);
    }
}

contract PufferPoolTest is TestHelper {
    using ECDSA for bytes32;
    using SafeTransferLib for address;
    using SafeTransferLib for address payable;

    event DepositRateChanged(uint256 oldValue, uint256 newValue);

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
    function testDeposit(address depositor, uint256 depositAmount) public assumeEOA(depositor) {
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

    // Fuzz test to test rounding error for exchange rate 1:1
    function testDepositAndRedeemRoundingError(address depositor, uint256 depositAmount) public assumeEOA(depositor) {
        depositAmount = bound(depositAmount, 0.01 ether, 1_000_000 ether);

        // Give out ETH
        vm.deal(depositor, depositAmount);
        vm.deal(address(withdrawalPool), 10_000_000 ether);

        vm.startPrank(depositor);
        assertEq(pool.balanceOf(depositor), 0, "recipient pufETH amount before deposit");

        uint256 minted = pool.depositETH{ value: depositAmount }();

        pool.approve(address(withdrawalPool), type(uint256).max);
        uint256 withdrawAmount = withdrawalPool.withdrawETH(depositor, minted);

        vm.stopPrank();

        assertTrue(depositAmount >= withdrawAmount, "rounding error");
    }

    // Fuzz test to test rounding error
    function testDepositAndRedeemRoundingErrorForDifferentExchangeRate(address depositor, uint256 depositAmount)
        public
        assumeEOA(depositor)
    {
        vm.roll(50401);

        depositAmount = bound(depositAmount, 0.01 ether, 1_000_000 ether);

        // Give out ETH
        vm.deal(depositor, depositAmount);
        vm.deal(address(withdrawalPool), 10_000_000 ether);

        assertEq(pool.getPufETHtoETHExchangeRate(), 1 ether, "exchange rate before");

        pufferProtocol.proofOfReserve({
            ethAmount: 10_000 ether,
            lockedETH: 320 ether,
            pufETHTotalSupply: 10_000 ether,
            blockNumber: 50350,
            guardianSignatures: _getGuardianEOASignatures(
                LibGuardianMessages.getProofOfReserveMessage({
                    ethAmount: 10_000 ether,
                    lockedETH: 320 ether,
                    pufETHTotalSupply: 10_000 ether,
                    blockNumber: 50350
                })
                )
        });
        vm.stopPrank();

        assertEq(pool.getPufETHtoETHExchangeRate(), 1.032 ether, "exchange rate after");

        vm.startPrank(depositor);
        assertEq(pool.balanceOf(depositor), 0, "recipient pufETH amount before deposit");

        uint256 minted = pool.depositETH{ value: depositAmount }();

        pool.approve(address(withdrawalPool), type(uint256).max);
        uint256 withdrawAmount = withdrawalPool.withdrawETH(depositor, minted);

        vm.stopPrank();

        assertTrue(depositAmount >= withdrawAmount, "rounding error");
    }

    // Test Alice and Bob depositing
    function testMultipleDeposits() public {
        address bob = makeAddr("bob");
        address alice = makeAddr("alice");

        vm.deal(bob, 100 ether);
        vm.deal(alice, 100 ether);

        vm.startPrank(bob);
        pool.depositETH{ value: 6 ether }();
        assertEq(pool.balanceOf(bob), 6 ether, "bob balance");

        vm.startPrank(alice);
        uint256 minted = pool.depositETH{ value: 10 ether }();

        assertEq(minted, 10 ether, "amounts dont match");
        assertEq(pool.balanceOf(alice), 10 ether, "alice balance");
    }

    // Test burning of pufETH
    function testBurn(address depositor) public assumeEOA(depositor) {
        uint256 amount = 5 ether;
        vm.deal(depositor, amount);

        vm.startPrank(depositor);
        uint256 pufETHAmount = pool.depositETH{ value: amount }();
        assertTrue(pufETHAmount != 0, "invalid pufETH amount");

        pool.burn(pufETHAmount);

        assertTrue(0 == pool.balanceOf(depositor));
    }

    function testDepositForOneWei() public {
        uint256 minted = pool.depositETH{ value: 1 }();
        assertEq(minted, 1, "minted 1 wei");
    }

    function testRatioChange() public {
        // total supply 0 means ratio is 1:1
        uint256 minted = pool.depositETH{ value: 1 ether }();
        assertEq(minted, 1 ether, "minted amount");

        // Simulate rewards of 1 ETH
        address(pool).safeTransferETH(1 ether);

        // Fast forward 50400 blocks ~ 7 days
        vm.roll(50401);

        pufferProtocol.proofOfReserve({
            ethAmount: 2 ether,
            lockedETH: 0,
            pufETHTotalSupply: 1 ether,
            blockNumber: 50401,
            guardianSignatures: _getGuardianEOASignatures(
                LibGuardianMessages.getProofOfReserveMessage({
                    ethAmount: 2 ether,
                    lockedETH: 0 ether,
                    pufETHTotalSupply: 1 ether,
                    blockNumber: 50401
                })
                )
        });
        vm.stopPrank();

        // total supply is 1
        // total eth = 2
        // ratio is 1/2 = 0.5, mint 0.5 pufETH to caller

        minted = pool.depositETH{ value: 1 ether }();

        assertEq(minted, 0.5 ether, "ratio didn't change");
    }

    function testRatioChangeSandwichAttack(uint256 numberOfValidators, uint256 attackerAmount) internal {
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

        // @todo revisit this
        // assertTrue(
        //     attacker.balance < (attackerAmount - (gasConsumedForWithdrawal + gasConsumedForDeposit)),
        //     "attacker is in profit"
        // );
        // assertApproxEqRel(attacker.balance, 10 ether, 1e16, "balance is bad"); // diff 1%
    }

    function testStorageS() public {
        PufferPoolStorage memory data = pufferProtocol.getPuferPoolStorage();
        assertEq(data.lastUpdate, 0, "last update");
    }

    function testRecoverERC20() public {
        vm.expectRevert(abi.encodeWithSelector(IPufferPool.InvalidToken.selector, address(pool)));
        pool.recoverERC20(address(pool));

        ERC20 token = new Mock();
        token.transfer(address(pool), token.balanceOf(address(this)));

        assertEq(token.balanceOf(pufferProtocol.TREASURY()), 0, "token balance");

        pool.recoverERC20(address(token));

        assertEq(token.balanceOf(pufferProtocol.TREASURY()), 1_000_000 ether, "token balance after");
    }
}
