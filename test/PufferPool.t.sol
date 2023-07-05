// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferPoolMockUpgrade } from "test/mocks/PufferPoolMockUpgrade.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";

contract PufferPoolTest is Test {
    PufferPool pool;
    SafeProxyFactory proxyFactory;
    Safe safeImplementation;

    function setUp() public {
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run();
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
        uint256 result = PufferPoolMockUpgrade(address(pool)).returnSomething();

        PufferPoolMockUpgrade newImplementation = new PufferPoolMockUpgrade();
        pool.upgradeTo(address(newImplementation));

        result = PufferPoolMockUpgrade(address(pool)).returnSomething();
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

    // Deposit should revert when trying to deposit too small amount
    function testDepositRevertsForTooSmallAmount() public {
        vm.expectRevert(IPufferPool.AmountTooSmall.selector);
        pool.deposit{ value: 0.005 ether }(makeAddr("recipient"));
    }
}
