// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferModuleFactory } from "puffer/PufferModuleFactory.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { PufferOracle } from "puffer/PufferOracle.sol";
import { PufferProtocolDeployment } from "./DeploymentStructs.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { NoRestakingModule } from "puffer/NoRestakingModule.sol";
import { PufferVaultMainnet } from "pufETH/PufferVaultMainnet.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { GenerateAccessManagerCallData } from "pufETHScript/GenerateAccessManagerCallData.sol";
import { ROLE_ID_OPERATIONS, ROLE_ID_PUFFER_PROTOCOL } from "pufETHScript/Roles.sol";

uint64 constant ROLE_ID_DAO = 77;
uint64 constant ROLE_ID_GUARDIANS = 88;
uint64 constant ROLE_ID_PAUSER = 999;

contract SetupAccess is BaseScript {
    AccessManager internal accessManager;

    PufferProtocolDeployment internal pufferDeployment;

    function run(PufferProtocolDeployment memory deployment, address DAO) external broadcast {
        pufferDeployment = deployment;
        accessManager = AccessManager(payable(deployment.accessManager));

        // We do one multicall to setup everything
        bytes[] memory rolesCalldatas = _grantRoles(DAO);
        bytes[] memory pufferProtocolRoles = _setupPufferProtocolRoles();
        bytes[] memory noRestakingModuleRoles = _setupNoRestakingModuleRoles();
        bytes[] memory validatorTicketRoles = _setupValidatorTicketsAccess();
        bytes[] memory vaultMainnetAccess = _setupPufferVaultMainnetAccess();
        bytes[] memory pufferOracleAccess = _setupPufferOracleAccess();

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

        calldatas[9] = noRestakingModuleRoles[0];
        calldatas[10] = noRestakingModuleRoles[1];
        calldatas[11] = noRestakingModuleRoles[2];

        calldatas[12] = validatorTicketRoles[0];
        calldatas[13] = validatorTicketRoles[1];

        calldatas[14] = vaultMainnetAccess[0];
        calldatas[15] = vaultMainnetAccess[1];

        calldatas[16] = pufferOracleAccess[0];
        calldatas[17] = pufferOracleAccess[1];

        accessManager.multicall(calldatas);

        // This will be executed by the operations multisig on mainnet
        bytes memory cd = new GenerateAccessManagerCallData().run(deployment.pufferVault, deployment.pufferProtocol);
        (bool s,) = address(accessManager).call(cd);
        require(s, "failed setupAccess GenerateAccessManagerCallData");
    }

    function _setupPufferOracleAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        // Only for PufferProtocol
        bytes4[] memory protocolSelectors = new bytes4[](1);
        protocolSelectors[0] = PufferOracle.provisionNode.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferOracle,
            protocolSelectors,
            ROLE_ID_PUFFER_PROTOCOL
        );

        // DAO selectors
        bytes4[] memory daoSelectors = new bytes4[](1);
        daoSelectors[0] = PufferOracle.setMintPrice.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferDeployment.pufferOracle, daoSelectors, ROLE_ID_DAO
        );

        return calldatas;
    }

    function _setupPufferVaultMainnetAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = PufferVaultMainnet.burn.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferVault,
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        bytes4[] memory daoSelectors = new bytes4[](1);
        daoSelectors[0] = PufferVaultMainnet.setDailyWithdrawalLimit.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferVault,
            daoSelectors,
            ROLE_ID_OPERATIONS //@todo?
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
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = GuardianModule.setGuardianEnclaveMeasurements.selector;
        selectors[1] = GuardianModule.addGuardian.selector;
        selectors[2] = GuardianModule.removeGuardian.selector;
        selectors[3] = GuardianModule.changeThreshold.selector;

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferDeployment.guardianModule, selectors, ROLE_ID_DAO
        );
    }

    function _setupUpgradeableBeacon() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = UpgradeableBeacon.upgradeTo.selector;

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            PufferModuleFactory(pufferDeployment.moduleFactory).PUFFER_MODULE_BEACON(),
            selectors,
            ROLE_ID_DAO
        );
    }

    function _setupNoRestakingModuleRoles() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = IPufferModule.callStake.selector;
        selectors[1] = IPufferModule.call.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.NoRestakingModule,
            selectors,
            ROLE_ID_PUFFER_PROTOCOL
        );

        bytes4[] memory selectorsForGuardians = new bytes4[](1);
        selectorsForGuardians[0] = NoRestakingModule.postRewardsRoot.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.NoRestakingModule,
            selectorsForGuardians,
            ROLE_ID_GUARDIANS
        );

        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = NoRestakingModule.collectRewards.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.NoRestakingModule,
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
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
        selectors[2] = PufferProtocol.changeModule.selector;
        selectors[3] = UUPSUpgradeable.upgradeToAndCall.selector;
        selectors[4] = PufferProtocol.setValidatorLimitPerModule.selector;
        selectors[5] = PufferProtocol.changeMinimumVTAmount.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            selectors,
            ROLE_ID_DAO
        );

        bytes4[] memory guardianSelectors = new bytes4[](3);
        guardianSelectors[0] = PufferProtocol.skipProvisioning.selector;
        guardianSelectors[1] = PufferProtocol.retrieveBond.selector;
        guardianSelectors[2] = PufferProtocol.postFullWithdrawalsRoot.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            guardianSelectors,
            ROLE_ID_GUARDIANS
        );

        bytes4[] memory publicSelectors = new bytes4[](3);
        publicSelectors[0] = PufferProtocol.registerValidatorKey.selector;
        publicSelectors[1] = PufferProtocol.depositValidatorTickets.selector;
        publicSelectors[2] = PufferProtocol.withdrawValidatorTickets.selector;

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
        calldatas[2] =
            abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_PAUSER, pufferDeployment.pauser, 0);

        return calldatas;
    }
}
