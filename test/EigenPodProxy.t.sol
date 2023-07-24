// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { DeployBeacon } from "scripts/DeployBeacon.s.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import "forge-std/console.sol";

contract EigenPodProxyV2Mock is EigenPodProxy {
    constructor() EigenPodProxy(IEigenPodManager(address(0))) {
        // do nothing
    }

    function getSomething() external pure returns (uint256 number) {
        return 225883;
    }
}

contract EigenPodProxyTest is Test {
    UpgradeableBeacon beacon;
    address payable alice = payable(makeAddr("alice"));
    address payable bob = payable(makeAddr("bob"));

    address beaconOwner = makeAddr("beaconOwner");

    function setUp() public {
        (, beacon) = new DeployBeacon().run();

        // Transfer ownership from 'default tx sender' in foundry to beaconOwner
        vm.prank(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
        beacon.transferOwnership(beaconOwner);
    }

    function testSetup() public {
        address eigenPodProxy = address(
            new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (alice, IPufferPool(address(this)))))
        );

        assertEq(EigenPodProxy(payable(eigenPodProxy)).podProxyOwner(), alice, "owner");
        assertEq(
            EigenPodProxy(payable(eigenPodProxy)).podProxyManager(),
            address(this),
            "In production PufferPool will be the manager"
        );
    }

    // Tests the upgrade of two eigen pod proxies
    function testUpgradeBeaconProxy() public {
        address eigenPodProxy = address(
            new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (alice, IPufferPool(address(this)))))
        );

        assertEq(EigenPodProxy(payable(eigenPodProxy)).podProxyOwner(), alice, "alice owner");
        assertEq(
            EigenPodProxy(payable(eigenPodProxy)).podProxyManager(),
            address(this),
            "In production PufferPool will be the manager"
        );

        (bool success, bytes memory returndata) =
            address(eigenPodProxy).call(abi.encodeCall(EigenPodProxyV2Mock.getSomething, ()));

        // Expect no return data, but no revert because we have fallback in EigenPodProxy
        // because of that it just returns empty return data
        assertEq(returndata.length, 0);

        address eigenPodProxyTwo = address(
            new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (bob, IPufferPool(address(this)))))
        );

        // // Both Eigen pod proxies should return empty data
        (success, returndata) = address(eigenPodProxyTwo).call(abi.encodeCall(EigenPodProxyV2Mock.getSomething, ()));
        assertEq(returndata.length, 0);

        assertEq(EigenPodProxy(payable(eigenPodProxyTwo)).podProxyOwner(), bob, "bob owner");
        assertEq(
            EigenPodProxy(payable(eigenPodProxyTwo)).podProxyManager(),
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
}
