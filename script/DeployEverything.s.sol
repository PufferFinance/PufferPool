// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { DeployGuardians } from "script/DeployGuardians.s.sol";
import { DeployPuffer } from "script/DeployPuffer.s.sol";
import { SetupAccess } from "script/SetupAccess.s.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { DeployPufETH, PufferDeployment } from "pufETHScript/DeployPufETH.s.sol";
import { UpgradePufETH } from "pufETHScript/UpgradePufETH.s.sol";
import { DeployPufferOracle } from "script/DeployPufferOracle.s.sol";
import { GuardiansDeployment, PufferProtocolDeployment } from "./DeploymentStructs.sol";

/**
 * @title Deploy all protocol contracts
 * @author Puffer Finance
 * @notice Deploys pufETH (upgrade it in test environment), Guardians, Oracle, Puffer, and sets up the access control
 * @dev Example on how to run the script
 *      forge script script/DeployEverything.s.sol:DeployEverything --rpc-url=$RPC_URL --sig 'run(address[] calldata, uint256)' "[$DEV_WALLET]" 1 --broadcast
 */
contract DeployEverything is BaseScript {
    address DAO;

    function run(address[] calldata guardians, uint256 threshold) public returns (PufferProtocolDeployment memory) {
        PufferProtocolDeployment memory deployment;

        // 1. Deploy pufETH
        // @todo In test environment, we need to deploy pufETH first, in prod, we just do the upgrade
        // AccessManager is part of the pufETH deployment
        PufferDeployment memory puffETHDeployment = new DeployPufETH().run();

        deployment.pufferVault = puffETHDeployment.pufferVault;
        deployment.pufferDepositor = puffETHDeployment.pufferDepositor;
        deployment.stETH = puffETHDeployment.stETH;
        deployment.weth = puffETHDeployment.weth;
        deployment.accessManager = puffETHDeployment.accessManager;

        GuardiansDeployment memory guardiansDeployment =
            new DeployGuardians().run(AccessManager(puffETHDeployment.accessManager), guardians, threshold);

        address pufferOracle = new DeployPufferOracle().run(
            puffETHDeployment.accessManager, guardiansDeployment.guardianModule, puffETHDeployment.pufferVault
        );

        // 2. Upgrade the vault
        new UpgradePufETH().run(puffETHDeployment, pufferOracle);

        PufferProtocolDeployment memory pufferDeployment = new DeployPuffer().run(
            guardiansDeployment, puffETHDeployment.pufferVault, puffETHDeployment.weth, pufferOracle
        );

        pufferDeployment.pufferDepositor = puffETHDeployment.pufferDepositor;
        pufferDeployment.pufferVault = puffETHDeployment.pufferVault;
        pufferDeployment.stETH = puffETHDeployment.stETH;
        pufferDeployment.weth = puffETHDeployment.weth;
        pufferDeployment.timelock = puffETHDeployment.timelock;

        // `anvil` in the terminal
        if (_localAnvil) {
            DAO = _broadcaster;
        } else if (isAnvil()) {
            // Tests environment `forge test ...`
            DAO = makeAddr("DAO");
        } else {
            // Testnet deployments
            DAO = _broadcaster;
        }

        new SetupAccess().run(pufferDeployment, DAO);

        _writeJson(pufferDeployment);

        return pufferDeployment;
    }

    function _writeJson(PufferProtocolDeployment memory deployment) internal {
        string memory obj = "";

        vm.serializeAddress(obj, "protocol", deployment.pufferProtocol);
        vm.serializeAddress(obj, "dao", DAO);
        vm.serializeAddress(obj, "guardianModule", deployment.guardianModule);
        vm.serializeAddress(obj, "accessManager", deployment.accessManager);

        vm.serializeAddress(obj, "enclaveVerifier", deployment.enclaveVerifier);
        vm.serializeAddress(obj, "moduleBeacon", deployment.beacon);
        vm.serializeAddress(obj, "moduleManager", deployment.moduleManager);
        vm.serializeAddress(obj, "validatorTicket", deployment.validatorTicket);
        vm.serializeAddress(obj, "oracle", deployment.pufferOracle);
        vm.serializeAddress(obj, "depositor", deployment.pufferDepositor);
        vm.serializeAddress(obj, "vault", deployment.pufferVault);
        vm.serializeAddress(obj, "stETH/stETH Mock", deployment.stETH);
        vm.serializeAddress(obj, "weth/weth Mock", deployment.weth);

        string memory finalJson = vm.serializeString(obj, "", "");
        vm.writeJson(finalJson, "./output/puffer.json");
    }
}
