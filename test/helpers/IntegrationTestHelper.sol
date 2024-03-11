// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferProtocolDeployment } from "script/DeploymentStructs.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferModuleFactory } from "puffer/PufferModuleFactory.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { IEnclaveVerifier } from "puffer/interface/IEnclaveVerifier.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";

contract IntegrationTestHelper is Test {
    PufferProtocol public pufferProtocol;
    UpgradeableBeacon public beacon;
    PufferModuleFactory public moduleFactory;

    GuardianModule public guardianModule;

    AccessManager public accessManager;
    IEnclaveVerifier public verifier;

    function deployContracts() public virtual {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 18_722_775);

        address[] memory guardians = new address[](1);
        guardians[0] = address(this);

        _deployAndLabel(guardians, 1);
    }

    function deployContractsGoerli() public virtual {
        vm.createSelectFork(vm.rpcUrl("goerli"), 9717928);

        address[] memory guardians = new address[](1);
        guardians[0] = address(this);

        _deployAndLabel(guardians, 1);
    }

    function _deployAndLabel(address[] memory guardians, uint256 threshold) internal {
        // Deploy everything with one script
        PufferProtocolDeployment memory pufferDeployment = new DeployEverything().run(guardians, threshold);

        pufferProtocol = PufferProtocol(payable(pufferDeployment.pufferProtocol));
        vm.label(address(pufferProtocol), "PufferProtocol");
        accessManager = AccessManager(pufferDeployment.accessManager);
        vm.label(address(accessManager), "AccessManager");
        verifier = IEnclaveVerifier(pufferDeployment.enclaveVerifier);
        vm.label(address(verifier), "EnclaveVerifier");
        guardianModule = GuardianModule(payable(pufferDeployment.guardianModule));
        vm.label(address(guardianModule), "GuardianModule");
        beacon = UpgradeableBeacon(pufferDeployment.beacon);
        vm.label(address(beacon), "PufferModuleBeacon");
        moduleFactory = PufferModuleFactory(pufferDeployment.moduleFactory);
        vm.label(address(moduleFactory), "PufferModuleFactory");
    }
}
