// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { DeployBeacon } from "scripts/DeployBeacon.s.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { SlasherMock } from "test/mocks/SlasherMock.sol";
import { EigenPodManagerMock } from "eigenlayer-test/mocks/EigenPodManagerMock.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { IEigenPodWrapper } from "puffer/interface/IEigenPodWrapper.sol";
import { PufferPoolMock } from "test/mocks/PufferPoolMock.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";

contract EigenPodProxyV2Mock is EigenPodProxy {
    constructor() EigenPodProxy(IEigenPodManager(address(0)), ISlasher(address(0))) {
        // do nothing
    }

    function getSomething() external pure returns (uint256 number) {
        return 225883;
    }
}

contract EigenPodProxyV3Mock is EigenPodProxy {
    IEigenPodManager eigenPodManager = new EigenPodManagerMock();
    ISlasher slasher = new SlasherMock(IStrategyManager(address(0)), IDelegationManager(address(0)));

    constructor() EigenPodProxy(IEigenPodManager(eigenPodManager), slasher) { }

    function init(address payable owner, IPufferPool manager, address payable podRewardsRecipient, uint256 bond)
        public
    {
        _podRewardsRecipient = podRewardsRecipient;
        _bond = bond;
        _podProxyOwner = owner;
        _podProxyManager = manager;
        _previousStatus = IEigenPodWrapper.VALIDATOR_STATUS.INACTIVE;
        _eigenPodManager.createPod();
        ownedEigenPod = IEigenPodWrapper(address(_eigenPodManager.ownerToPod(address(this))));
    }

    function handleInactiveSkim() public {
        return _handleInactiveSkim();
    }

    function distributeConsensusRewards(uint256 amount) public {
        return _distributeConsensusRewards(amount);
    }

    function handleQuickWithdraw(uint256 amount) public {
        return _handleQuickWithdraw(amount);
    }

    function getPreviousStatus() public view returns (IEigenPodWrapper.VALIDATOR_STATUS) {
        return _previousStatus;
    }

    function setBondWithdrawn(bool _bondWithdrawn) public {
        bondWithdrawn = _bondWithdrawn;
    }
}

contract EigenPodProxyTest is Test {
    PufferPool pool;
    UpgradeableBeacon beacon;
    UpgradeableBeacon rewardsBeacon;
    address payable alice = payable(makeAddr("alice"));
    address payable bob = payable(makeAddr("bob"));
    address beaconOwner = makeAddr("beaconOwner");
    SafeProxyFactory proxyFactory;
    Safe safeImplementation;
    EigenPodProxy eigenPodProxy;

    modifier fromPool() {
        vm.startPrank(address(pool));
        _;
        vm.stopPrank();
    }

    function setUp() public {
        (, beacon,, rewardsBeacon) = new DeployBeacon().run(true);

        // Transfer ownership from 'default tx sender' in foundry to beaconOwner
        vm.prank(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
        beacon.transferOwnership(beaconOwner);

        pool = PufferPool(payable(address(new PufferPoolMock())));

        eigenPodProxy = EigenPodProxy(
            payable(
                address(
                    new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(pool)), 2 ether)))
                )
            )
        );

        // Give ETH to pool
        vm.deal(address(pool), 100 ether);

        vm.prank(address(pool));
        eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(alice, alice);
    }

    // Tests the setup
    function testSetup() public {
        assertEq(eigenPodProxy.getPodProxyManager(), address(pool), "Pool should be the manager");

        assertEq(eigenPodProxy.getPodProxyOwner(), alice, "alice should be the pool proxy owner");
        assertTrue(address(eigenPodProxy.getEigenPodManager()) != address(0), "Eigen pod manager shouldnt be address 0");

        // This acts as a second initializer, so it should revert if we try to call it again
        vm.expectRevert();
        eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(alice, alice);
    }

    // Activates the validator staking
    function testCallStakeShouldWork() public fromPool {
        bytes memory pubKey = abi.encodePacked("1234");

        assertEq(eigenPodProxy.getPubKey().length, 0, "pubkey shouldnt exist");

        eigenPodProxy.callStake{ value: 32 ether }({
            pubKey: pubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32("")
        });

        assertEq(eigenPodProxy.getPubKey(), pubKey, "pubkey");
    }

    // Stop registration should revert if the validator is already activated
    function testStopRegistrationReverts() public {
        testCallStakeShouldWork();
        vm.expectRevert(IEigenPodProxy.PodIsAlreadyStaking.selector);
        vm.prank(alice);
        eigenPodProxy.stopRegistraion();
    }

    // Test stop registration
    function testStopRegistration() public {
        assertEq(pool.balanceOf(alice), 0, "alice should not have pufETH");

        // Give 100 pufETH to eigen pod proxy
        deal(address(pool), address(eigenPodProxy), 100 ether);

        vm.prank(alice);
        eigenPodProxy.stopRegistraion();

        assertEq(pool.balanceOf(alice), 100 ether, "alice should get pufETH");
    }

    // Tests the upgrade of two eigen pod proxies
    function testUpgradeBeaconProxy() public {
        testSetup();

        (bool success, bytes memory returndata) =
            address(eigenPodProxy).call(abi.encodeCall(EigenPodProxyV2Mock.getSomething, ()));

        // Expect no return data, but no revert because we have fallback in EigenPodProxy
        // because of that it just returns empty return data
        assertEq(returndata.length, 0);

        address eigenPodProxyTwo = address(
            new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(this)), 2 ether)))
        );

        // // Both Eigen pod proxies should return empty data
        (success, returndata) = address(eigenPodProxyTwo).call(abi.encodeCall(EigenPodProxyV2Mock.getSomething, ()));
        assertEq(returndata.length, 0);

        assertEq(
            EigenPodProxy(payable(eigenPodProxyTwo)).getPodProxyManager(),
            address(this),
            "In production PufferPool will be the manager"
        );

        address newImplementation = address(new EigenPodProxyV2Mock());
        vm.prank(beaconOwner); // It is the owner in test env
        beacon.upgradeTo(newImplementation);

        // // Both eigen pods should return "magic" now that they are upgraded
        assertEq(EigenPodProxyV2Mock(payable(eigenPodProxy)).getSomething(), 225883, "upgrade didnt work for alice");
        assertEq(EigenPodProxyV2Mock(payable(eigenPodProxyTwo)).getSomething(), 225883, "failed upgrade for bob");
    }

    function testChangePodRewardsRecipient() public {
        vm.prank(alice);
        eigenPodProxy.updatePodRewardsRecipient(payable(address(bob)));
        vm.prank(bob);
        vm.expectRevert();
        eigenPodProxy.updatePodRewardsRecipient(payable(address(alice)));
    }

    /* TODO: Fix so that AVS we mock is whitelisted
    // TODO: Needs to change when we make dictionary for AVS info and payments
    function testAvsRewardsProxy() public {
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon), address(proxyFactory), address(safeImplementation));
        vm.label(address(pool), "PufferPool");

        address payable eigenPodProxyAddress = payable(
            address(
                new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (alice, IPufferPool(address(pool)), alice, 2 ether)))
            )
        );
        EigenPodProxy eigenPodProxy = EigenPodProxy(eigenPodProxyAddress);
        vm.prank(alice);
        eigenPodProxy.enableSlashing(address(bob));

        uint256 aliceBalanceBefore = alice.balance;
        uint256 poolBalanceBefore = address(pool).balance;

        vm.deal(bob, 2 ether);
        vm.prank(bob);
        payable(address(eigenPodProxy)).call{ value: 1 ether }("");

        // After sending 1 eth AVS rewards, both alice and the pool should receive funds
        assert(alice.balance > aliceBalanceBefore);
        assert(address(pool).balance > poolBalanceBefore);

        // Total funds received should add up to total funds sent to fallback
        assertEq((alice.balance - aliceBalanceBefore) + (address(pool).balance - poolBalanceBefore), 1 ether);

        // Alice shold get 5% of 1 eth, pool gets the rest
        assertEq(alice.balance - aliceBalanceBefore, 5 * 10 ** 16);
        assertEq(address(pool).balance - poolBalanceBefore, 95 * 10 ** 16);
    }
    */

    // function testExecutionRewardsProxy() public {
    //     (proxyFactory, safeImplementation) = new DeploySafe().run();
    //     (pool,) =
    //     new DeployPufferPool().run(address(beacon), address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
    //     vm.label(address(pool), "PufferPool");

    //     address payable eigenPodProxyAddress = payable(
    //         address(
    //             new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(pool)), 2 ether)))
    //         )
    //     );
    //     EigenPodProxy eigenPodProxy = EigenPodProxy(eigenPodProxyAddress);
    //     uint256 aliceBalanceBefore = alice.balance;
    //     uint256 poolBalanceBefore = address(pool).balance;

    //     // Set Owner and Pod Rewards Recipient
    //     vm.prank(address(pool));
    //     eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(alice, alice);

    //     vm.prank(address(1));
    //     vm.deal(address(1), 2 ether);
    //     assertEq(address(1).balance, 2 ether);

    //     payable(address(eigenPodProxy)).call{ value: 1 ether }("");

    //     // After sending 1 eth AVS rewards, both alice and the pool should receive funds
    //     assert(alice.balance > aliceBalanceBefore);
    //     assert(address(pool).balance > poolBalanceBefore);

    //     // Total funds received should add up to total funds sent to fallback
    //     assertEq((alice.balance - aliceBalanceBefore) + (address(pool).balance - poolBalanceBefore), 1 ether);

    //     // Alice shold get 5% of 1 eth, pool gets the rest
    //     assertEq(alice.balance - aliceBalanceBefore, 5 * 10 ** 16);
    //     assertEq(address(pool).balance - poolBalanceBefore, 95 * 10 ** 16);
    // }

    // function testConsensusRewardsActiveProxy() public {
    //     (proxyFactory, safeImplementation) = new DeploySafe().run();
    //     (pool,) =
    //     new DeployPufferPool().run(address(beacon), address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
    //     vm.label(address(pool), "PufferPool");

    //     EigenPodProxyV3Mock eigenPodProxy = new EigenPodProxyV3Mock();
    //     eigenPodProxy.init(alice, IPufferPool(address(pool)), alice, 2 ether);

    //     uint256 aliceBalanceBefore = alice.balance;
    //     uint256 poolBalanceBefore = address(pool).balance;

    //     vm.deal(address(eigenPodProxy), 5 ether);

    //     eigenPodProxy.distributeConsensusRewards(2 ether);

    //     assert(alice.balance > aliceBalanceBefore);
    //     assert(address(pool).balance > poolBalanceBefore);

    //     // Total funds received should add up to total funds sent to fallback
    //     assertEq((alice.balance - aliceBalanceBefore) + (address(pool).balance - poolBalanceBefore), 2 ether);

    //     // Alice shold get 5% of 1 eth, pool gets the rest
    //     assertEq(alice.balance - aliceBalanceBefore, 10 * 10 ** 16);
    //     assertEq(address(pool).balance - poolBalanceBefore, 190 * 10 ** 16);
    // }

    // function testQuickWithdrawProxy() public {
    //     (proxyFactory, safeImplementation) = new DeploySafe().run();
    //     (pool,) =
    //     new DeployPufferPool().run(address(beacon),address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
    //     vm.label(address(pool), "PufferPool");

    //     EigenPodProxyV3Mock eigenPodProxy = new EigenPodProxyV3Mock();
    //     eigenPodProxy.init(alice, IPufferPool(address(pool)), alice, 2 ether);

    //     vm.deal(address(eigenPodProxy), 2 ether);

    //     uint256 aliceBalanceBefore = alice.balance;
    //     uint256 poolBalanceBefore = address(pool).balance;
    //     // Status is not withdrawn to start
    //     assert(IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN != eigenPodProxy.getPreviousStatus());

    //     eigenPodProxy.handleQuickWithdraw(2 ether);

    //     // Status changes to withdrawn
    //     assert(IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN == eigenPodProxy.getPreviousStatus());
    //     assert(alice.balance > aliceBalanceBefore);
    //     assert(address(pool).balance > poolBalanceBefore);
    //     assertEq(
    //         (alice.balance - aliceBalanceBefore) + (address(pool).balance - poolBalanceBefore)
    //             + address(eigenPodProxy).balance,
    //         2 ether
    //     );
    //     // 1 eth will remain on the contract
    //     assertEq(address(eigenPodProxy).balance, 1 ether);
    //     assertEq(alice.balance - aliceBalanceBefore, 5 * 10 ** 16);
    //     assertEq(address(pool).balance - poolBalanceBefore, 95 * 10 ** 16);
    // }

    // function testCompleteSlowWithdrawProxy() public {
    //     (proxyFactory, safeImplementation) = new DeploySafe().run();
    //     (pool,) =
    //     new DeployPufferPool().run(address(beacon),address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
    //     vm.label(address(pool), "PufferPool");

    //     EigenPodProxyV3Mock eigenPodProxy = new EigenPodProxyV3Mock();
    //     eigenPodProxy.init(alice, IPufferPool(address(pool)), alice, 2 ether);

    //     // TODO: This should basically just check the pool's withdrawFromProtocol function
    // }

    // function testRewardsAfterBondWithdrawnProxy() public {
    //     (proxyFactory, safeImplementation) = new DeploySafe().run();
    //     (pool,) =
    //     new DeployPufferPool().run(address(beacon),address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
    //     vm.label(address(pool), "PufferPool");

    //     EigenPodProxyV3Mock eigenPodProxy = new EigenPodProxyV3Mock();
    //     eigenPodProxy.init(alice, IPufferPool(address(pool)), alice, 2 ether);

    //     eigenPodProxy.setBondWithdrawn(true);

    //     uint256 aliceBalanceBefore = alice.balance;
    //     uint256 poolBalanceBefore = address(pool).balance;

    //     vm.prank(bob);
    //     vm.deal(bob, 2 ether);
    //     payable(address(eigenPodProxy)).call{ value: 1 ether }("");

    //     // Alice should get no funds, and pool should receive everything
    //     assertEq(alice.balance, aliceBalanceBefore);
    //     assertEq(address(pool).balance, poolBalanceBefore + 1 ether);
    // }
}
