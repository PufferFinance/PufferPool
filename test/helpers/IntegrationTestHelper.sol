// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import { DeployBeacon } from "scripts/DeployBeacon.s.sol";
import { PufferPool } from "puffer/PufferPool.sol";

contract IntegrationTestHelper is Test {
    address safeProxyFactory = 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2;
    address safeImplementation = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;

    UpgradeableBeacon beacon;
    UpgradeableBeacon rewardsSplitterBeacon;
    PufferPool pool;

    function deployContracts() public {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 17784482);

        (, beacon) = new DeployBeacon().run(false);

        (pool,) = new DeployPufferPool().run(address(beacon), safeProxyFactory, safeImplementation);
        vm.label(address(pool), "PufferPool");
    }
}
