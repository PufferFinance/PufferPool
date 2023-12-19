// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { DeployGuardians } from "script/DeployGuardians.s.sol";
import { DeployPuffer } from "script/DeployPuffer.s.sol";
import { PufferDeployment } from "script/DeploymentStructs.sol";
import { GuardiansDeployment } from "script/DeploymentStructs.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferModuleFactory } from "puffer/PufferModuleFactory.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferDeployment } from "script/DeploymentStructs.sol";
import { IEnclaveVerifier } from "puffer/interface/IEnclaveVerifier.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";

contract IntegrationTestHelper is Test {
    PufferPool public pool;
    PufferProtocol public pufferProtocol;
    IWithdrawalPool public withdrawalPool;
    UpgradeableBeacon public beacon;
    PufferModuleFactory public moduleFactory;

    GuardianModule public guardianModule;

    AccessManager public accessManager;
    IEnclaveVerifier public verifier;

    function deployContracts() public virtual {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 18_722_775);

        address[] memory guardians = new address[](3);
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
        PufferDeployment memory pufferDeployment = new DeployEverything().run(guardians, threshold);

        pufferProtocol = PufferProtocol(payable(pufferDeployment.pufferProtocol));
        vm.label(address(pufferProtocol), "PufferProtocol");
        accessManager = AccessManager(pufferDeployment.accessManager);
        vm.label(address(accessManager), "AccessManager");
        pool = PufferPool(payable(pufferDeployment.pufferPool));
        vm.label(address(pool), "PufferPool");
        withdrawalPool = IWithdrawalPool(pufferDeployment.withdrawalPool);
        vm.label(address(withdrawalPool), "WithdrawalPool");
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
