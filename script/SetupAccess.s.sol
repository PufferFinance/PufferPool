// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { console } from "forge-std/console.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { Multicall } from "openzeppelin/utils/Multicall.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferModuleManager } from "puffer/PufferModuleManager.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { PufferProtocolDeployment } from "./DeploymentStructs.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { PufferVaultV2 } from "pufETH/PufferVaultV2.sol";
import { OperationsCoordinator } from "puffer/OperationsCoordinator.sol";
import { GenerateAccessManagerCallData } from "pufETHScript/GenerateAccessManagerCallData.sol";
import {
    ROLE_ID_OPERATIONS_MULTISIG,
    ROLE_ID_OPERATIONS_PAYMASTER,
    ROLE_ID_PUFFER_PROTOCOL,
    ROLE_ID_DAO,
    ROLE_ID_OPERATIONS_COORDINATOR
} from "pufETHScript/Roles.sol";

contract SetupAccess is Script {
    AccessManager internal accessManager;

    PufferProtocolDeployment internal pufferDeployment;

    function run(PufferProtocolDeployment memory deployment, address DAO, address paymaster) external {
        pufferDeployment = deployment;
        accessManager = AccessManager(payable(deployment.accessManager));

        // We do one multicall to setup everything
        bytes[] memory calldatas = _generateAccessCalldata({
            rolesCalldatas: _grantRoles(DAO, paymaster),
            pufferProtocolRoles: _setupPufferProtocolRoles(),
            validatorTicketRoles: _setupValidatorTicketsAccess(),
            vaultMainnetAccess: _setupPufferVaultMainnetAccess(),
            pufferOracleAccess: _setupPufferOracleAccess(),
            moduleManagerAccess: _setupPufferModuleManagerAccess(),
            roleLabels: _labelRoles(),
            coordinatorAccess: _setupCoordinatorAccess()
        });

        bytes memory multicallData = abi.encodeCall(Multicall.multicall, (calldatas));
        console.logBytes(multicallData);
        // (bool s,) = address(accessManager).call(multicallData);
        // require(s, "failed setupAccess GenerateAccessManagerCallData 1");

        // This will be executed by the operations multisig on mainnet
        bytes memory cd = new GenerateAccessManagerCallData().run(deployment.pufferVault, deployment.pufferDepositor);
        console.logBytes(cd);
        // (s,) = address(accessManager).call(cd);
        // require(s, "failed setupAccess GenerateAccessManagerCallData");
    }

    function _generateAccessCalldata(
        bytes[] memory rolesCalldatas,
        bytes[] memory pufferProtocolRoles,
        bytes[] memory validatorTicketRoles,
        bytes[] memory vaultMainnetAccess,
        bytes[] memory pufferOracleAccess,
        bytes[] memory moduleManagerAccess,
        bytes[] memory roleLabels,
        bytes[] memory coordinatorAccess
    ) internal view returns (bytes[] memory calldatas) {
        calldatas = new bytes[](26);
        calldatas[0] = _setupGuardianModuleRoles();
        calldatas[1] = _setupEnclaveVerifierRoles();
        calldatas[2] = rolesCalldatas[0];
        calldatas[3] = rolesCalldatas[1];
        calldatas[4] = rolesCalldatas[2];
        calldatas[5] = rolesCalldatas[3];
        calldatas[6] = rolesCalldatas[4];

        calldatas[7] = pufferProtocolRoles[0];
        calldatas[8] = pufferProtocolRoles[1];
        calldatas[9] = pufferProtocolRoles[2];

        calldatas[10] = validatorTicketRoles[0];
        calldatas[11] = validatorTicketRoles[1];

        calldatas[12] = vaultMainnetAccess[0];
        calldatas[13] = vaultMainnetAccess[1];

        calldatas[14] = pufferOracleAccess[0];
        calldatas[15] = pufferOracleAccess[1];
        calldatas[16] = pufferOracleAccess[2];

        calldatas[17] = moduleManagerAccess[0];
        calldatas[18] = moduleManagerAccess[1];
        calldatas[19] = moduleManagerAccess[2];

        calldatas[20] = roleLabels[0];
        calldatas[21] = roleLabels[1];
        calldatas[22] = roleLabels[2];
        calldatas[23] = roleLabels[3];

        calldatas[24] = coordinatorAccess[0];
        calldatas[25] = coordinatorAccess[1];
    }

    function _labelRoles() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](4);

        calldatas[0] = abi.encodeWithSelector(AccessManager.labelRole.selector, ROLE_ID_DAO, "Puffer DAO");

        calldatas[1] =
            abi.encodeWithSelector(AccessManager.labelRole.selector, ROLE_ID_PUFFER_PROTOCOL, "Puffer Protocol");

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.labelRole.selector, ROLE_ID_OPERATIONS_PAYMASTER, "Operations Paymaster"
        );

        calldatas[3] =
            abi.encodeWithSelector(AccessManager.labelRole.selector, ROLE_ID_OPERATIONS_MULTISIG, "Operations Multisig");

        return calldatas;
    }

    function _setupPufferModuleManagerAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        // Dao selectors
        bytes4[] memory selectors = new bytes4[](11);
        selectors[0] = PufferModuleManager.createNewRestakingOperator.selector;
        selectors[1] = PufferModuleManager.callModifyOperatorDetails.selector;
        selectors[2] = PufferModuleManager.callOptIntoSlashing.selector;
        selectors[3] = PufferModuleManager.callUpdateMetadataURI.selector;
        selectors[4] = PufferModuleManager.callUndelegate.selector;
        selectors[5] = PufferModuleManager.callDelegateTo.selector;
        selectors[6] = PufferModuleManager.updateAVSRegistrationSignatureProof.selector;
        selectors[7] = PufferModuleManager.callRegisterOperatorToAVS.selector;
        selectors[8] = PufferModuleManager.callRegisterOperatorToAVSWithChurn.selector;
        selectors[9] = PufferModuleManager.callDeregisterOperatorFromAVS.selector;
        selectors[10] = PufferModuleManager.callUpdateOperatorAVSSocket.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferDeployment.moduleManager, selectors, ROLE_ID_DAO
        );

        // Bot selectors
        bytes4[] memory botSelectors = new bytes4[](4);
        botSelectors[0] = PufferModuleManager.callQueueWithdrawals.selector;
        botSelectors[1] = PufferModuleManager.callVerifyAndProcessWithdrawals.selector;
        botSelectors[2] = PufferModuleManager.callWithdrawNonBeaconChainETHBalanceWei.selector;
        botSelectors[3] = PufferModuleManager.callCompleteQueuedWithdrawals.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.moduleManager,
            botSelectors,
            ROLE_ID_OPERATIONS_PAYMASTER
        );

        // Public selectors
        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = PufferModuleManager.callVerifyWithdrawalCredentials.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.moduleManager,
            publicSelectors,
            accessManager.PUBLIC_ROLE()
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

        bytes4[] memory operationsSelectors = new bytes4[](1);
        operationsSelectors[0] = PufferOracleV2.setTotalNumberOfValidators.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferOracle,
            operationsSelectors,
            ROLE_ID_OPERATIONS_MULTISIG
        );

        bytes4[] memory coordinatorSelectors = new bytes4[](1);
        coordinatorSelectors[0] = PufferOracleV2.setMintPrice.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferOracle,
            coordinatorSelectors,
            ROLE_ID_OPERATIONS_COORDINATOR
        );

        return calldatas;
    }

    function _setupPufferVaultMainnetAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        bytes4[] memory daoSelectors = new bytes4[](1);
        daoSelectors[0] = PufferVaultV2.setDailyWithdrawalLimit.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferVault,
            daoSelectors,
            ROLE_ID_DAO
        );

        bytes4[] memory protocolSelectors = new bytes4[](1);
        protocolSelectors[0] = PufferVaultV2.transferETH.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferVault,
            protocolSelectors,
            ROLE_ID_PUFFER_PROTOCOL
        );

        return calldatas;
    }

    function _setupValidatorTicketsAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = ValidatorTicket.setProtocolFeeRate.selector;
        selectors[1] = ValidatorTicket.setGuardiansFeeRate.selector;

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

    function _setupEnclaveVerifierRoles() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EnclaveVerifier.removeLeafX509.selector;

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferDeployment.enclaveVerifier, selectors, ROLE_ID_DAO
        );
    }

    function _setupPufferProtocolRoles() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = PufferProtocol.createPufferModule.selector;
        selectors[1] = PufferProtocol.setModuleWeights.selector;
        selectors[2] = PufferProtocol.setValidatorLimitPerModule.selector;
        selectors[3] = PufferProtocol.changeMinimumVTAmount.selector;
        selectors[4] = PufferProtocol.setVTPenalty.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            selectors,
            ROLE_ID_DAO
        );

        bytes4[] memory paymasterSelectors = new bytes4[](3);
        paymasterSelectors[0] = PufferProtocol.provisionNode.selector;
        paymasterSelectors[1] = PufferProtocol.skipProvisioning.selector;
        paymasterSelectors[2] = PufferProtocol.batchHandleWithdrawals.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            paymasterSelectors,
            ROLE_ID_OPERATIONS_PAYMASTER
        );

        bytes4[] memory publicSelectors = new bytes4[](4);
        publicSelectors[0] = PufferProtocol.registerValidatorKey.selector;
        publicSelectors[1] = PufferProtocol.depositValidatorTickets.selector;
        publicSelectors[2] = PufferProtocol.withdrawValidatorTickets.selector;
        publicSelectors[3] = PufferProtocol.revertIfPaused.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
    }

    function _setupCoordinatorAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        bytes4[] memory operationsSelectors = new bytes4[](1);
        operationsSelectors[0] = OperationsCoordinator.setPriceChangeToleranceBps.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.operationsCoordinator,
            operationsSelectors,
            ROLE_ID_OPERATIONS_MULTISIG
        );

        bytes4[] memory paymasterSelectors = new bytes4[](1);
        paymasterSelectors[0] = OperationsCoordinator.setValidatorTicketMintPrice.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.operationsCoordinator,
            paymasterSelectors,
            ROLE_ID_OPERATIONS_PAYMASTER
        );

        return calldatas;
    }

    function _grantRoles(address DAO, address paymaster) internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](5);

        calldatas[0] = abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_DAO, DAO, 0);
        calldatas[1] = abi.encodeWithSelector(
            AccessManager.grantRole.selector, ROLE_ID_PUFFER_PROTOCOL, pufferDeployment.pufferProtocol, 0
        );
        calldatas[2] =
            abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_OPERATIONS_PAYMASTER, paymaster, 0);

        calldatas[3] = abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_OPERATIONS_COORDINATOR, DAO, 0);
        calldatas[4] = abi.encodeWithSelector(
            AccessManager.grantRole.selector, ROLE_ID_OPERATIONS_COORDINATOR, pufferDeployment.operationsCoordinator, 0
        );

        return calldatas;
    }
}
