// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferModuleFactory } from "puffer/PufferModuleFactory.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { PufferDeployment } from "./DeploymentStructs.sol";

uint64 constant ROLE_ID_PUFFER_PROTOCOL = 1;
uint64 constant ROLE_ID_DAO = 77;
uint64 constant ROLE_ID_GUARDIANS = 88;
uint64 constant ROLE_ID_PAUSER = 999;

contract SetupAccess is BaseScript {
    AccessManager internal accessManager;

    PufferDeployment internal pufferDeployment;

    function run(PufferDeployment memory deployment, address DAO) external broadcast {
        pufferDeployment = deployment;
        accessManager = AccessManager(payable(deployment.accessManager));

        // We do one multicall to setup everything
        bytes[] memory rolesCalldatas = _grantRoles(DAO);
        bytes[] memory pufferProtocolRoles = _setupPufferProtocolRoles();
        bytes[] memory pufferPoolRoles = _setupPufferPoolRoles();
        bytes[] memory noRestakingModuleRoles = _setupNoRestakingModuleRoles();

        bytes[] memory calldatas = new bytes[](15);
        calldatas[0] = _setupGuardianModuleRoles();
        calldatas[1] = _setupEnclaveVerifierRoles();
        calldatas[2] = _setupWithdrawalPoolRoles();
        calldatas[3] = _setupUpgradeableBeacon();
        calldatas[4] = rolesCalldatas[0];
        calldatas[5] = rolesCalldatas[1];
        calldatas[6] = rolesCalldatas[2];

        calldatas[7] = pufferProtocolRoles[0];
        calldatas[8] = pufferProtocolRoles[1];
        calldatas[9] = pufferProtocolRoles[2];

        calldatas[10] = pufferPoolRoles[0];
        calldatas[11] = pufferPoolRoles[1];

        calldatas[12] = noRestakingModuleRoles[0];
        calldatas[13] = noRestakingModuleRoles[1];
        calldatas[14] = noRestakingModuleRoles[2];

        // calldatas[16] = _setupPauser();

        accessManager.multicall(calldatas);
    }

    function _setupPauser() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = AccessManager.setTargetClosed.selector;

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, address(accessManager), selectors, ROLE_ID_PAUSER
        );
    }

    function _setupWithdrawalPoolRoles() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = bytes4(hex"4782f779"); // IWithdrawalPool.withdrawETH.selector;
        selectors[1] = bytes4(hex"945fca09"); // IWithdrawalPool.withdrawETH Permit version

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.withdrawalPool,
            selectors,
            accessManager.PUBLIC_ROLE()
        );
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

    function _setupPufferPoolRoles() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = PufferPool.transferETH.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferPool,
            selectors,
            ROLE_ID_PUFFER_PROTOCOL
        );

        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = PufferPool.depositETH.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.pufferPool,
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
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
        selectorsForGuardians[0] = bytes4(hex"abfaad62"); // signature for `function postRewardsRoot(bytes32 root, uint256 blockNumber)`

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferDeployment.NoRestakingModule,
            selectorsForGuardians,
            ROLE_ID_GUARDIANS
        );

        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = bytes4(hex"6f06f422"); // collectRewards

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

        bytes4[] memory selectors = new bytes4[](10);
        selectors[0] = PufferProtocol.setProtocolFeeRate.selector;
        selectors[1] = PufferProtocol.setSmoothingCommitments.selector;
        selectors[2] = PufferProtocol.createPufferModule.selector;
        selectors[3] = PufferProtocol.setModuleWeights.selector;
        selectors[4] = PufferProtocol.setValidatorLimitPerInterval.selector;
        selectors[5] = PufferProtocol.changeModule.selector;
        selectors[6] = bytes4(hex"4f1ef286"); // signature for UUPS.upgradeToAndCall(address newImplementation, bytes memory data)
        selectors[7] = PufferProtocol.setGuardiansFeeRate.selector;
        selectors[8] = PufferProtocol.setWithdrawalPoolRate.selector;
        selectors[9] = PufferProtocol.setValidatorLimitPerModule.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            selectors,
            ROLE_ID_DAO
        );

        bytes4[] memory guardianSelectors = new bytes4[](4);
        guardianSelectors[0] = PufferProtocol.skipProvisioning.selector;
        guardianSelectors[1] = PufferProtocol.stopValidator.selector;
        guardianSelectors[2] = PufferProtocol.proofOfReserve.selector;
        guardianSelectors[3] = PufferProtocol.postFullWithdrawalsRoot.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferDeployment.pufferProtocol),
            guardianSelectors,
            ROLE_ID_GUARDIANS
        );

        bytes4[] memory publicSelectors = new bytes4[](2);
        publicSelectors[0] = PufferProtocol.registerValidatorKey.selector;
        publicSelectors[1] = PufferProtocol.registerValidatorKeyPermit.selector;

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
