// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import { DeployPuffer } from "script/DeployPuffer.s.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { DeployGuardians } from "script/DeployGuardians.s.sol";
import { GuardiansDeployment } from "script/DeploymentStructs.sol";

contract IntegrationTestHelper is Test {
    address safeProxyFactory = 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2; // mainnet
    address safeImplementation = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552; // mainnet

    PufferPool pool;

    function deployContracts() public {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 17784482);

        address[] memory guardians = new address[](1);
        guardians[0] = address(this);

        // 1. Deploy guardians safe
        GuardiansDeployment memory guardiansDeployment = new DeployGuardians().run(guardians, 1, "");

        new DeployPuffer().run(guardiansDeployment);
        // vm.label(address(pool), "PufferPool");
    }

    function deployContractsGoerli() public {
        vm.createSelectFork(vm.rpcUrl("goerli"), 9717928);

        address[] memory guardians = new address[](1);
        guardians[0] = address(this);

        GuardiansDeployment memory guardiansDeployment = new DeployGuardians().run(guardians, 1, "");

        new DeployPuffer().run(guardiansDeployment);
        // vm.label(address(pool), "PufferPool");
    }
}
