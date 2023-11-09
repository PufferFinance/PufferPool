// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";

uint64 constant ROLE_ID_PUFFER_PROTOCOL = 1;
uint64 constant ROLE_ID_DAO = 77;
uint64 constant ROLE_ID_GUARDIANS = 88;
uint64 constant ROLE_ID_PAUSER = 999;

contract SetupAccess is BaseScript {
    string internal pufferDeployment = vm.readFile(string.concat("./output/puffer.json"));

    string internal guardiansDeployment = guardiansDeployment =
        vm.readFile(string.concat("./output/", Strings.toString(block.chainid), "-guardians.json"));

    AccessManager internal accessManager = AccessManager(stdJson.readAddress(guardiansDeployment, ".accessManager"));

    address internal guardians = stdJson.readAddress(guardiansDeployment, ".guardians");
    address internal guardianModule = stdJson.readAddress(guardiansDeployment, ".guardianModule");
    address internal pufferProtocol = stdJson.readAddress(pufferDeployment, ".PufferProtocol");
    address internal noRestakingStrategy = stdJson.readAddress(pufferDeployment, ".noRestakingStrategy");
    address internal withdrawalPool = stdJson.readAddress(pufferDeployment, ".withdrawalPool");
    address internal pufferPool = stdJson.readAddress(pufferDeployment, ".pufferPool");
    address internal enclaveVerifier = stdJson.readAddress(guardiansDeployment, ".enclaveVerifier");
    address internal pauser = stdJson.readAddress(guardiansDeployment, ".pauser");

    function run(address DAO) external broadcast {
        // We do one multicall to setup everything
        bytes[] memory rolesCalldatas = _grantRoles(DAO);
        bytes[] memory pufferProtocolRoles = _setupPufferProtocolRoles();
        bytes[] memory pufferPoolRoles = _setupPufferPoolRoles();
        bytes[] memory noRestakingStrategyRoles = _setupNoRestakingStrategyRoles();

        bytes[] memory calldatas = new bytes[](16);
        calldatas[0] = _setupGuardianModuleRoles();
        calldatas[1] = _setupEnclaveVerifierRoles();
        calldatas[2] = _setupWithdrawalPoolRoles();
        calldatas[3] = _setupUpgradeableBeacon();
        calldatas[4] = rolesCalldatas[0];
        calldatas[5] = rolesCalldatas[1];
        calldatas[6] = rolesCalldatas[2];
        calldatas[7] = rolesCalldatas[3];

        calldatas[8] = pufferProtocolRoles[0];
        calldatas[9] = pufferProtocolRoles[1];
        calldatas[10] = pufferProtocolRoles[2];

        calldatas[11] = pufferPoolRoles[0];
        calldatas[12] = pufferPoolRoles[1];

        calldatas[13] = noRestakingStrategyRoles[0];
        calldatas[14] = noRestakingStrategyRoles[1];
        calldatas[15] = noRestakingStrategyRoles[2];

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
            AccessManager.setTargetFunctionRole.selector, withdrawalPool, selectors, accessManager.PUBLIC_ROLE()
        );
    }

    function _setupGuardianModuleRoles() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = GuardianModule.setGuardianEnclaveMeasurements.selector;

        return
            abi.encodeWithSelector(AccessManager.setTargetFunctionRole.selector, guardianModule, selectors, ROLE_ID_DAO);
    }

    function _setupPufferPoolRoles() internal returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = PufferPool.transferETH.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferPool, selectors, ROLE_ID_PUFFER_PROTOCOL
        );

        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = PufferPool.depositETH.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, pufferPool, publicSelectors, accessManager.PUBLIC_ROLE()
        );

        return calldatas;
    }

    function _setupUpgradeableBeacon() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = UpgradeableBeacon.upgradeTo.selector;

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            PufferProtocol(pufferProtocol).PUFFER_STRATEGY_BEACON(),
            selectors,
            ROLE_ID_DAO
        );
    }

    function _setupNoRestakingStrategyRoles() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IPufferStrategy.callStake.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, noRestakingStrategy, selectors, ROLE_ID_PUFFER_PROTOCOL
        );

        bytes4[] memory selectorsForGuardians = new bytes4[](1);
        selectorsForGuardians[0] = bytes4(hex"abfaad62"); // signature for `function postRewardsRoot(bytes32 root, uint256 blockNumber)`

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, noRestakingStrategy, selectorsForGuardians, ROLE_ID_GUARDIANS
        );

        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = bytes4(hex"6f06f422"); // collectRewards

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            noRestakingStrategy,
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
    }

    function _setupEnclaveVerifierRoles() internal view returns (bytes memory) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EnclaveVerifier.removeLeafX509.selector;

        return abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, enclaveVerifier, selectors, ROLE_ID_DAO
        );
    }

    function _setupPufferProtocolRoles() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        bytes4[] memory selectors = new bytes4[](9);
        selectors[0] = PufferProtocol.setProtocolFeeRate.selector;
        selectors[1] = PufferProtocol.setSmoothingCommitments.selector;
        selectors[2] = PufferProtocol.createPufferStrategy.selector;
        selectors[3] = PufferProtocol.setStrategyWeights.selector;
        selectors[4] = PufferProtocol.setValidatorLimitPerInterval.selector;
        selectors[5] = PufferProtocol.changeStrategy.selector;
        selectors[6] = bytes4(hex"4f1ef286"); // signature for UUPS.upgradeToAndCall(address newImplementation, bytes memory data)
        selectors[7] = PufferProtocol.setGuardiansFeeRate.selector;
        selectors[8] = PufferProtocol.setWithdrawalPoolRate.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, address(pufferProtocol), selectors, ROLE_ID_DAO
        );

        bytes4[] memory guardianSelectors = new bytes4[](4);
        guardianSelectors[0] = PufferProtocol.skipProvisioning.selector;
        guardianSelectors[1] = PufferProtocol.stopValidator.selector;
        guardianSelectors[2] = PufferProtocol.proofOfReserve.selector;
        guardianSelectors[3] = PufferProtocol.postFullWithdrawalsRoot.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, address(pufferProtocol), guardianSelectors, ROLE_ID_GUARDIANS
        );

        bytes4[] memory publicSelectors = new bytes4[](1);
        publicSelectors[0] = PufferProtocol.registerValidatorKey.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(pufferProtocol),
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
    }

    function _grantRoles(address DAO) internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](4);

        calldatas[0] = abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_DAO, DAO, 0);
        calldatas[1] = abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_GUARDIANS, guardians, 0);
        calldatas[2] =
            abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_PUFFER_PROTOCOL, pufferProtocol, 0);
        calldatas[3] = abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_PAUSER, pauser, 0);

        return calldatas;
    }
}
