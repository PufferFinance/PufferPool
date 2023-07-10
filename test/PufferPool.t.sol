// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferPoolMockUpgrade } from "test/mocks/PufferPoolMockUpgrade.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import { DeployBeacon } from "scripts/DeployBeacon.s.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";

contract PufferPoolTest is Test {
    PufferPool pool;
    SafeProxyFactory proxyFactory;
    Safe safeImplementation;
    UpgradeableBeacon beacon;

    function setUp() public {
        (, beacon) = new DeployBeacon().run();
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon));
        vm.label(address(pool), "PufferPool");
    }

    // Test setup
    function testSetup() public {
        assertEq(pool.name(), "Puffer ETH");
        assertEq(pool.symbol(), "pufETH");
        assertEq(pool.paused(), false, "paused");
        assertEq(address(this), pool.owner(), "owner");

        vm.expectRevert("Initializable: contract is already initialized");
        pool.initialize();
    }

    // Test smart contract upgradeability (UUPS)
    function testUpgrade() public {
        vm.expectRevert();
        uint256 result = PufferPoolMockUpgrade(payable(address(pool))).returnSomething();

        PufferPoolMockUpgrade newImplementation = new PufferPoolMockUpgrade();
        pool.upgradeTo(address(newImplementation));

        result = PufferPoolMockUpgrade(payable(address(pool))).returnSomething();

        assertEq(result, 1337);
    }

    // Pause
    function testPause() public {
        assertEq(pool.paused(), false, "!paused");
        pool.pause();
        assertEq(pool.paused(), true, "paused");
    }

    // Resume
    function testResume() public {
        pool.pause();
        assertEq(pool.paused(), true, "paused");
        pool.resume();
        assertEq(pool.paused(), false, "resunmed");
    }

    // Create guardian account
    function testCreateGuardianAccount(bytes32 mrenclave) public {
        address[] memory owners = new address[](1);

        owners[0] = address(this);

        Safe safe = pool.createGuardianAccount({
            safeProxyFactory: address(proxyFactory),
            safeImplementation: address(safeImplementation),
            mrenclave: mrenclave,
            guardiansWallets: owners,
            guardiansEnclavePubKeys: new bytes[](0)
        });

        assertTrue(safe.isOwner(address(this)), "bad owner");
        assertEq(safe.getThreshold(), 1, "threshold");
    }

    // Fuzz test for creating Pod account
    function testCreatePodAccount(bytes32 mrenclave, address owner1, address owner2) public {
        vm.assume(owner1 != address(0)); // address(0) can't be used
        vm.assume(owner2 != address(0));
        vm.assume(owner1 != address(1));
        vm.assume(owner2 != address(1)); // address(1) is special and can't be used in {Safe}
        vm.assume(owner1 != owner2);

        address[] memory owners = new address[](2);

        owners[0] = owner1;
        owners[1] = owner2;

        Safe safe = pool.createPodAccount({
            safeProxyFactory: address(proxyFactory),
            safeImplementation: address(safeImplementation),
            mrenclave: mrenclave,
            podWallets: owners,
            podEnclavePubKeys: new bytes[](0)
        });

        assertTrue(safe.isOwner(address(owner1)), "bad owner");
        assertTrue(safe.isOwner(address(owner2)), "bad owner2");
        assertEq(safe.getThreshold(), 1, "threshold");
    }

    // Fuzz test for depositing ETH to PufferPool
    function testDeposit(address pufETHRecipient, uint256 depositAmount) public {
        vm.assume(pufETHRecipient != address(0));
        depositAmount = bound(depositAmount, 0.01 ether, 1_000_000 ether);

        assertEq(pool.balanceOf(pufETHRecipient), 0, "recipient pufETH amount before deposit");

        pool.deposit{ value: depositAmount }(pufETHRecipient);

        assertEq(pool.balanceOf(pufETHRecipient), depositAmount, "recipient pufETH amount");
    }

    // Deposits a random amount of ETH, gets pufETH in return, withdraws pufETH
    // should get the deposited ETH amount back
    function testDepositAndWtihdrawal(uint256 depositAmount) public {
        depositAmount = bound(depositAmount, 0.01 ether, 1_000_000 ether);
        address pufETHRecipient = makeAddr("pufETHRecipient");

        assertEq(pool.balanceOf(pufETHRecipient), 0, "recipient pufETH amount before deposit");

        pool.deposit{ value: depositAmount }(pufETHRecipient);

        uint256 pufETHRecipientBalance = pool.balanceOf(pufETHRecipient);

        vm.startPrank(pufETHRecipient);
        pool.approve(address(pool), pufETHRecipientBalance);

        pool.withdraw(pufETHRecipient, pufETHRecipientBalance);

        assertEq(depositAmount, pufETHRecipient.balance, "amounts don't match");
    }

    // Test multiple deposits, fake rewards, fake slashing and withdrawal of pufETH -> ETH
    function testMultipleDeposits() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        uint256 aliceAmount = 100 ether;
        pool.deposit{ value: aliceAmount }(alice);

        uint256 alicePufETHBalance = pool.balanceOf(alice);
        assertEq(alicePufETHBalance, aliceAmount); // first depositor got 1:1 conversion rate because totalSupply of pufETH is 0

        // 100 ETH deposited, 100 pufETH minted - 1:1 rate

        // Send fake rewards to pool
        // pool now has 25 ETH
        (bool success,) = payable(address(pool)).call{ value: 25 ether }("");
        require(success, "rewards failed");

        // Pool before deposit has 125 ETH and 100 pufETH total supply
        // conversion rate is 1.25
        uint256 bobAmount = 100 ether;
        pool.deposit{ value: bobAmount }(bob);

        // Pool now has 225 ETH (fake rewards + alice deposit + bob deposit)
        assertEq(225 ether, address(pool).balance, "pool eth amount first check");

        // Check that the bob got the right amount of pufETH tokens
        uint256 bobPufETHBalance = pool.balanceOf(bob);
        assertEq(bobPufETHBalance, 80 ether);

        // Check the total supply 100 pufETH from alice and 80 from bob
        assertEq(pool.totalSupply(), 180 ether, "pufETH total supply");

        // Send fake rewards to pool
        (success,) = payable(address(pool)).call{ value: 45 ether }("");
        require(success, "rewards failed");

        // 270 ETH in the pool and 180 pufETH mean 1.5 conversion rate
        assertEq(pool.getPufETHtoETHExchangeRate(), 1.5 ether, "conversion rate"); // conversion rate should be 1.5

        // Alice withdraws 70 pufETH for 105 ETH
        vm.prank(alice);
        pool.withdraw(alice, 70 ether);

        assertEq(105 ether, alice.balance, "alice amount");

        // Fake slashing of the pool
        vm.prank(address(pool));
        (success,) = payable(address(0)).call{ value: 65 ether }("");
        require(success, "fake slashing");

        assertEq(100 ether, address(pool).balance, "pool eth amount");
        assertEq(pool.totalSupply(), 110 ether, "pufETH total supply second check");

        // 100 eth / 110 pufETH => 0.90909090909090909 exchange rate
        assertEq(pool.getPufETHtoETHExchangeRate(), 0.90909090909090909 ether, "conversion rate after fake slashing"); // ~0.9

        vm.prank(bob);
        pool.withdraw(bob, 10 ether); // withdraw 10pufETH -> ETH

        // Bob should get ~9 ETH
        assertEq(9.0909090909090909 ether, bob.balance, "bob amount");

        // Assert leftover
        assertEq(100 ether - 9.0909090909090909 ether, address(pool).balance, "pool eth amount last check");
        assertEq(pool.totalSupply(), 100 ether, "pufETH total supply last check");

        // Withdraw the remaining pufETH, zeroing out ETH and pufETH total supply
        vm.prank(alice);
        pool.withdraw(alice, 30 ether);

        vm.prank(bob);
        pool.withdraw(bob, 70 ether);

        assertEq(0, address(pool).balance, "pool eth amount");
        assertEq(pool.totalSupply(), 0, "pufETH total supply last check");
    }

    // Deposit should revert when trying to deposit too small amount
    function testDepositRevertsForTooSmallAmount() public {
        vm.expectRevert(IPufferPool.AmountTooSmall.selector);
        pool.deposit{ value: 0.005 ether }(makeAddr("recipient"));
    }
}
