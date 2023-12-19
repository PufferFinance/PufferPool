// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { DeployGuardians } from "script/DeployGuardians.s.sol";
import { DeployPuffer } from "script/DeployPuffer.s.sol";
import { SetupAccess } from "script/SetupAccess.s.sol";
import { GuardiansDeployment, PufferDeployment } from "./DeploymentStructs.sol";

contract DeployEverything is BaseScript {
    address DAO;

    function run(address[] calldata guardians, uint256 threshold) public returns (PufferDeployment memory) {
        // Deploy guardians
        GuardiansDeployment memory guardiansDeployment = new DeployGuardians().run(guardians, threshold);

        PufferDeployment memory pufferDeployment = new DeployPuffer().run(guardiansDeployment);

        if (!isAnvil()) {
            DAO = _broadcaster;
        } else {
            DAO = makeAddr("DAO");
        }

        new SetupAccess().run(pufferDeployment, DAO);

        return pufferDeployment;
    }
}
