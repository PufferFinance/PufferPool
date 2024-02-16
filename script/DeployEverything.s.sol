// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { DeployGuardians } from "script/DeployGuardians.s.sol";
import { DeployPuffer } from "script/DeployPuffer.s.sol";
import { SetupAccess } from "script/SetupAccess.s.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { DeployPuffETH, PufferDeployment } from "pufETHScript/DeployPuffETH.s.sol";
import { UpgradePuffETH } from "pufETHScript/UpgradePuffETH.s.sol";
import { DeployPufferOracle } from "script/DeployPufferOracle.s.sol";
import { GuardiansDeployment, PufferProtocolDeployment } from "./DeploymentStructs.sol";

contract DeployEverything is BaseScript {
    address DAO;

    function run(address[] calldata guardians, uint256 threshold) public returns (PufferProtocolDeployment memory) {
        PufferProtocolDeployment memory deployment;

        // 1. Deploy pufETH
        // @todo In test environment, we need to deploy pufETH first, in prod, we just do the upgrade
        // AccessManager is part of the pufETH deployment
        PufferDeployment memory puffETHDeployment = new DeployPuffETH().run();

        deployment.pufferVault = puffETHDeployment.pufferVault;
        deployment.pufferDepositor = puffETHDeployment.pufferDepositor;
        deployment.stETH = puffETHDeployment.stETH;
        deployment.weth = puffETHDeployment.weth;
        deployment.accessManager = puffETHDeployment.accessManager;

        GuardiansDeployment memory guardiansDeployment =
            new DeployGuardians().run(AccessManager(puffETHDeployment.accessManager), guardians, threshold);

        address pufferOracle =
            new DeployPufferOracle().run(puffETHDeployment.accessManager, guardiansDeployment.guardianModule);

        // 2. Upgrade the vault
        new UpgradePuffETH().run(puffETHDeployment.pufferVault, puffETHDeployment.accessManager, pufferOracle);

        PufferProtocolDeployment memory pufferDeployment = new DeployPuffer().run(
            guardiansDeployment, puffETHDeployment.pufferVault, puffETHDeployment.weth, pufferOracle
        );

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
