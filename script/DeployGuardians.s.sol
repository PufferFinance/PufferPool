// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";
import { GuardiansDeployment } from "./DeploymentStructs.sol";

// forge script script/1_DeployGuardians.s.sol:DeployGuardians --rpc-url=$EPHEMERY_RPC_URL --sig 'run(address[] calldata, uint256)' "[0x5F9a7EA6A79Ef04F103bfe7BD45dA65476a5155C]" 1
contract DeployGuardians is BaseScript {
    address internal safeProxy;
    address internal safeImplementation;

    function run(address[] calldata guardians, uint256 threshold)
        public
        broadcast
        returns (GuardiansDeployment memory)
    {
        // Broadcaster is the deployer
        AccessManager accessManager = new AccessManager(_broadcaster);
        vm.label(address(accessManager), "AccessManager");

        EnclaveVerifier verifier = new EnclaveVerifier(100, address(accessManager));

        GuardianModule module = new GuardianModule(verifier, guardians, threshold, address(accessManager));

        address DAO = payable(vm.envOr("DAO", makeAddr("DAO")));

        string memory obj = "";
        vm.serializeAddress(obj, "accessManager", address(accessManager));
        vm.serializeAddress(obj, "guardianModule", address(module));
        vm.serializeAddress(obj, "enclaveVerifier", address(verifier));
        vm.serializeAddress(obj, "pauser", DAO);

        string memory finalJson = vm.serializeString(obj, "", "");

        vm.writeJson(finalJson, string.concat("./output/", Strings.toString(block.chainid), "-guardians.json"));

        GuardiansDeployment memory deployment;
        deployment.accessManager = address(accessManager);
        deployment.guardianModule = address(module);
        deployment.enclaveVerifier = address(verifier);
        deployment.pauser = DAO;

        return deployment;
    }
}
