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
import { IDelayedWithdrawalRouter } from "eigenlayer/interfaces/IDelayedWithdrawalRouter.sol";
import { SlasherMock } from "test/mocks/SlasherMock.sol";
import { EigenPodManagerMock } from "eigenlayer-test/mocks/EigenPodManagerMock.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { PufferPoolMock } from "test/mocks/PufferPoolMock.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";

contract EigenPodProxyV2Mock is EigenPodProxy {
    constructor() EigenPodProxy(IEigenPodManager(address(0)), ISlasher(address(0))) {
        // do nothing
    }

    function getSomething() external pure returns (uint256 number) {
        return 225883;
    }
}

contract EigenPodMock {
    // Address(1) is the delayed withdrawal mock address
    function delayedWithdrawalRouter() public pure returns (IDelayedWithdrawalRouter) {
        return IDelayedWithdrawalRouter(address(1));
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
        _podProxyOwner = owner;
        _pool = manager;
        _previousStatus = IEigenPod.VALIDATOR_STATUS.INACTIVE;
        _eigenPodManager.createPod();
        eigenPod = IEigenPod(address(_eigenPodManager.ownerToPod(address(this))));
    }

    function handleQuickWithdraw(uint256 amount) public { }

    function getPreviousStatus() public view returns (IEigenPod.VALIDATOR_STATUS) {
        return _previousStatus;
    }
}

contract EigenPodProxyTest is Test {
    PufferPool pool;
    UpgradeableBeacon beacon;
    UpgradeableBeacon rewardsBeacon;
    address payable alice = payable(makeAddr("alice"));
    address payable bob = payable(makeAddr("bob"));
    address beaconOwner = makeAddr("beaconOwner");

    // For Simplifying tests, we are assigning eigenpodMock to address(0)
    address eigenPodMock = address(0);
    // And DelayedWithdrawalRouter to address(1)
    address delayedWithdrawalMock = address(1);

    SafeProxyFactory proxyFactory;
    Safe safeImplementation;
    EigenPodProxy eigenPodProxy;

    mapping(address addr => bool skip) _skipAddresses;

    modifier fromPool() {
        vm.startPrank(address(pool));
        _;
        vm.stopPrank();
    }

    modifier fuzzAddresses(address addr) virtual {
        vm.assume(_skipAddresses[addr] == false);
        _;
    }

    function setUp() public {
        (, beacon) = new DeployBeacon().run(true);

        // Transfer ownership from 'default tx sender' in foundry to beaconOwner
        vm.prank(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
        beacon.transferOwnership(beaconOwner);

        pool = PufferPool(payable(address(new PufferPoolMock())));

        eigenPodProxy = EigenPodProxy(
            payable(
                address(
                    new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(pool)))))
                )
            )
        );

        // Give ETH to pool
        vm.deal(address(pool), 100 ether);

        vm.prank(address(pool));
        eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(alice, alice);

        // In this test setup we set EigenPodMock to address(0)
        EigenPodMock eigenPodMockDeployment = new EigenPodMock();
        // Change the bytecode of address(0) to EigenPodMock bytecode
        vm.etch(eigenPodMock, address(eigenPodMockDeployment).code);

        _skipAddresses[address(pool)] = true;
        _skipAddresses[address(eigenPodProxy)] = true;
        _skipAddresses[eigenPodMock] = true;
        _skipAddresses[delayedWithdrawalMock] = true;
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

        eigenPodProxy.callStake{ value: 32 ether }({
            pubKey: pubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32("")
        });
    }

    // Test stop registration
    function testReleaseBond() public {
        assertEq(pool.balanceOf(alice), 0, "alice should not have pufETH");

        // Give 100 pufETH to eigen pod proxy
        deal(address(pool), address(eigenPodProxy), 100 ether);

        // Only PufferPool can call this
        vm.prank(address(pool));
        eigenPodProxy.releaseBond(100 ether);

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
            new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(this)))))
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

    // Tests rewards recipient change, revers if not called by the owner
    function testChangePodRewardsRecipient() public {
        vm.prank(alice);
        eigenPodProxy.updatePodRewardsRecipient(payable(address(bob)));

        vm.expectRevert(IEigenPodProxy.Unauthorized.selector);
        vm.prank(bob);
        eigenPodProxy.updatePodRewardsRecipient(payable(address(alice)));
    }

    // Execution rewards distirbution
    function testDistributeExecutionRewards(address blockProducer) public fuzzAddresses(blockProducer) {
        // For execution rewards msg.sender must be address other than EigenLayer's router
        uint256 poolBalanceBefore = address(pool).balance;

        vm.deal(blockProducer, 100 ether);
        (bool success,) = address(eigenPodProxy).call{ value: 100 ether }("");
        require(success, "failed");
        assertEq(alice.balance, 5 ether, "alice did not receive 5% execution reward");
        assertEq(address(pool).balance, poolBalanceBefore + 95 ether, "pool should get the rest");
    }

    // Consensus rewards distirbution
    function testDistributeConsensusRewards() public {
        uint256 poolBalanceBefore = address(pool).balance;

        vm.deal(delayedWithdrawalMock, 100 ether);
        vm.startPrank(delayedWithdrawalMock);
        (bool success,) = address(eigenPodProxy).call{ value: 100 ether }("");
        require(success, "failed");
        assertEq(alice.balance, 10 ether, "alice did not receive 5% consensus reward");
        assertEq(address(pool).balance, poolBalanceBefore + 90 ether, "pool should get the rest");
    }
}
