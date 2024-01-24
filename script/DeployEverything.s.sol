// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { DeployGuardians } from "script/DeployGuardians.s.sol";
import { DeployPuffer } from "script/DeployPuffer.s.sol";
import { SetupAccess } from "script/SetupAccess.s.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { DeployPuffETH, PufferDeployment } from "pufETHScript/DeployPuffETH.s.sol";
import { GuardiansDeployment, PufferProtocolDeployment } from "./DeploymentStructs.sol";

contract DeployEverything is BaseScript {
    address DAO;

    function run(address[] calldata guardians, uint256 threshold) public returns (PufferProtocolDeployment memory) {
        PufferDeployment memory puffETHDeployment = new DeployPuffETH().run();

        // Deploy guardians
        GuardiansDeployment memory guardiansDeployment =
            new DeployGuardians().run(AccessManager(puffETHDeployment.accessManager), guardians, threshold);

        PufferProtocolDeployment memory pufferDeployment =
            new DeployPuffer().run(guardiansDeployment, puffETHDeployment.pufferVault, puffETHDeployment.weth);

        pufferDeployment.pufferDepositor = puffETHDeployment.pufferDepositor;
        pufferDeployment.pufferVault = puffETHDeployment.pufferVault;
        pufferDeployment.stETH = puffETHDeployment.stETH;
        pufferDeployment.weth = puffETHDeployment.weth;

        if (!isAnvil()) {
            DAO = _broadcaster;
        } else {
            DAO = makeAddr("DAO");
        }

        new SetupAccess().run(pufferDeployment, DAO);

        return pufferDeployment;
    }
}
