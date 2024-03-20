// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferModuleManager } from "puffer/PufferModuleManager.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { PufferProtocolDeployment } from "./DeploymentStructs.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { PufferVaultV2 } from "pufETH/PufferVaultV2.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { GenerateAccessManagerCallData } from "pufETHScript/GenerateAccessManagerCallData.sol";
import {
    ROLE_ID_OPERATIONS,
    ROLE_ID_PUFFER_PROTOCOL,
    ROLE_ID_GUARDIANS,
    ROLE_ID_DAO,
    ROLE_ID_PUFFER_ORACLE
} from "pufETHScript/Roles.sol";

contract SetupAccess is BaseScript {
    AccessManager internal accessManager;

    PufferProtocolDeployment internal pufferDeployment;

    function run(PufferProtocolDeployment memory deployment, address DAO) external broadcast {
        pufferDeployment = deployment;
        accessManager = AccessManager(payable(deployment.accessManager));

        // We do one multicall to setup everything
        bytes[] memory rolesCalldatas = _grantRoles(DAO);
        bytes[] memory pufferProtocolRoles = _setupPufferProtocolRoles();
        bytes[] memory validatorTicketRoles = _setupValidatorTicketsAccess();
        bytes[] memory vaultMainnetAccess = _setupPufferVaultMainnetAccess();
        bytes[] memory pufferOracleAccess = _setupPufferOracleAccess();
        bytes[] memory moduleManagerAccess = _setupPufferModuleManagerAccess();

        bytes[] memory calldatas = new bytes[](18);
        calldatas[0] = _setupGuardianModuleRoles();
        calldatas[1] = _setupEnclaveVerifierRoles();
        calldatas[2] = _setupUpgradeableBeacon();
        calldatas[3] = rolesCalldatas[0];
        calldatas[4] = rolesCalldatas[1];
        calldatas[5] = rolesCalldatas[2];

        calldatas[6] = pufferProtocolRoles[0];
        calldatas[7] = pufferProtocolRoles[1];
        calldatas[8] = pufferProtocolRoles[2];

        calldatas[9] = validatorTicketRoles[0];
        calldatas[10] = validatorTicketRoles[1];

        calldatas[11] = vaultMainnetAccess[0];
        calldatas[12] = vaultMainnetAccess[1];
        calldatas[13] = vaultMainnetAccess[2];

        calldatas[14] = pufferOracleAccess[0];
        calldatas[15] = pufferOracleAccess[1];
        calldatas[16] = pufferOracleAccess[2];

        calldatas[17] = moduleManagerAccess[0];

        accessManager.multicall(calldatas);

        // This will be executed by the operations multisig on mainnet
        bytes memory cd = new GenerateAccessManagerCallData().run(deployment.pufferVault, deployment.pufferDepositor);
        (bool s,) = address(accessManager).call(cd);
        require(s, "failed setupAccess GenerateAccessManagerCallData");
    }

    function _setupPufferModuleManagerAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](1);

        // Dao selectors
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = PufferModuleManager.createNewRestakingOperator.selector;
        selectors[1] = PufferModuleManager.callModifyOperatorDetails.selector;
        selectors[2] = PufferModuleManager.callOptIntoSlashing.selector;
        selectors[3] = PufferModuleManager.callDelegateTo.selector;
        selectors[4] = PufferModuleManager.callUndelegate.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferDeployment.moduleManager, selectors, ROLE_ID_DAO
        );

        return calldatas;
    }

    function _setupPufferOracleAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        // Only for PufferProtocol
        bytes4[] memory protocolSelectors = new bytes4[](2);
        protocolSelectors[0] = PufferOracleV2.provisionNode.selector;
        protocolSelectors[1] = PufferOracleV2.exitValidators.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferOracle,
            protocolSelectors,
            ROLE_ID_PUFFER_PROTOCOL
        );

        // DAO selectors
        bytes4[] memory daoSelectors = new bytes4[](1);
        daoSelectors[0] = PufferOracleV2.setMintPrice.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferDeployment.pufferOracle, daoSelectors, ROLE_ID_DAO
        );

        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = PufferOracleV2.setTotalNumberOfValidators.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferOracle,
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
    }

    function _setupPufferVaultMainnetAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = PufferVaultV2.burn.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferVault,
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        bytes4[] memory daoSelectors = new bytes4[](1);
        daoSelectors[0] = PufferVaultV2.setDailyWithdrawalLimit.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferVault,
            daoSelectors,
            ROLE_ID_OPERATIONS //@todo?
        );

        bytes4[] memory protocolSelectors = new bytes4[](1);
        protocolSelectors[0] = PufferVaultV2.transferETH.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferVault,
            protocolSelectors,
            ROLE_ID_PUFFER_PROTOCOL
        );

        return calldatas;
    }

    function _setupValidatorTicketsAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = ValidatorTicket.setProtocolFeeRate.selector;
        selectors[1] = UUPSUpgradeable.upgradeToAndCall.selector;
        selectors[2] = ValidatorTicket.setGuardiansFeeRate.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferDeployment.validatorTicket, selectors, ROLE_ID_DAO
        );

        bytes4[] memory publicSelectors = new bytes4[](2);
        publicSelectors[0] = ValidatorTicket.purchaseValidatorTicket.selector;
        publicSelectors[1] = ValidatorTicket.burn.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.validatorTicket,
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
    }

    function _setupGuardianModuleRoles() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = GuardianModule.setGuardianEnclaveMeasurements.selector;
        selectors[1] = GuardianModule.addGuardian.selector;
        selectors[2] = GuardianModule.removeGuardian.selector;
        selectors[3] = GuardianModule.setEjectionThreshold.selector;
        selectors[4] = GuardianModule.setThreshold.selector;

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferDeployment.guardianModule, selectors, ROLE_ID_DAO
        );
    }

    function _setupUpgradeableBeacon() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = UpgradeableBeacon.upgradeTo.selector;

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            PufferModuleManager(pufferDeployment.moduleManager).PUFFER_MODULE_BEACON(),
            selectors,
            ROLE_ID_DAO
        );
    }

    function _setupEnclaveVerifierRoles() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EnclaveVerifier.removeLeafX509.selector;

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferDeployment.enclaveVerifier, selectors, ROLE_ID_DAO
        );
    }

    function _setupPufferProtocolRoles() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = PufferProtocol.createPufferModule.selector;
        selectors[1] = PufferProtocol.setModuleWeights.selector;
        selectors[2] = UUPSUpgradeable.upgradeToAndCall.selector;
        selectors[3] = PufferProtocol.setValidatorLimitPerModule.selector;
        selectors[4] = PufferProtocol.changeMinimumVTAmount.selector;
        selectors[5] = PufferProtocol.setVTPenalty.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            selectors,
            ROLE_ID_DAO
        );

        bytes4[] memory guardianSelectors = new bytes4[](1);
        guardianSelectors[0] = PufferProtocol.skipProvisioning.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            guardianSelectors,
            ROLE_ID_GUARDIANS //@todo guardians use signatures, remove
        );

        bytes4[] memory publicSelectors = new bytes4[](7);
        publicSelectors[0] = PufferProtocol.registerValidatorKey.selector;
        publicSelectors[1] = PufferProtocol.depositValidatorTickets.selector;
        publicSelectors[2] = PufferProtocol.withdrawValidatorTickets.selector;
        publicSelectors[3] = PufferProtocol.provisionNode.selector;
        publicSelectors[4] = PufferProtocol.batchHandleWithdrawals.selector;
        publicSelectors[5] = PufferProtocol.skipProvisioning.selector;
        publicSelectors[6] = PufferProtocol.revertIfPaused.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
    }

    function _grantRoles(address DAO) internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        calldatas[0] = abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_DAO, DAO, 0);
        calldatas[1] = abi.encodeWithSelector(
            AccessManager.grantRole.selector, ROLE_ID_PUFFER_PROTOCOL, pufferDeployment.pufferProtocol, 0
        );
        calldatas[2] = abi.encodeWithSelector(
            AccessManager.grantRole.selector, ROLE_ID_PUFFER_ORACLE, pufferDeployment.pufferOracle, 0
        );

        return calldatas;
    }
}
