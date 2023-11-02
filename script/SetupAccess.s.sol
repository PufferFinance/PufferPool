// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";

uint64 constant ROLE_ID_PUFFER_PROTOCOL = 1;
uint64 constant ROLE_ID_DAO = 77;
uint64 constant ROLE_ID_GUARDIANS = 88;

contract SetupAccess is BaseScript {
    string internal pufferDeployment = vm.readFile(string.concat("./output/puffer.json"));

    string internal guardiansDeployment = guardiansDeployment =
        vm.readFile(string.concat("./output/", Strings.toString(block.chainid), "-guardians.json"));

    AccessManager internal accessManager = AccessManager(stdJson.readAddress(guardiansDeployment, ".accessManager"));

    address internal guardians = stdJson.readAddress(guardiansDeployment, ".guardians");
    address internal guardianModule = stdJson.readAddress(guardiansDeployment, ".guardianModule");
    address internal pufferProtocol = stdJson.readAddress(pufferDeployment, ".PufferProtocol");
    address internal noRestakingStrategy = stdJson.readAddress(pufferDeployment, ".noRestakingStrategy");
    address internal pufferPool = stdJson.readAddress(pufferDeployment, ".pufferPool");
    address internal enclaveVerifier = stdJson.readAddress(guardiansDeployment, ".enclaveVerifier");

    function run(address DAO) external broadcast {
        _grantRoles(DAO);
        _setupPufferProtocolRoles();
        _setupGuardianModuleRoles();
        _setupPufferPoolRoles();
        _setupNoRestakingStrategyRoles();
        _setupUpgradeableBeacon();
        _setupEnclaveVerifierRoles();
    }

    function _setupGuardianModuleRoles() internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = GuardianModule.setGuardianEnclaveMeasurements.selector;

        accessManager.setTargetFunctionRole(guardianModule, selectors, ROLE_ID_DAO);
    }

    function _setupPufferPoolRoles() internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = PufferPool.transferETH.selector;

        accessManager.setTargetFunctionRole(pufferPool, selectors, ROLE_ID_PUFFER_PROTOCOL);
    }

    function _setupUpgradeableBeacon() internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = UpgradeableBeacon.upgradeTo.selector;

        accessManager.setTargetFunctionRole(
            PufferProtocol(pufferProtocol).PUFFER_STRATEGY_BEACON(), selectors, ROLE_ID_DAO
        );
    }

    function _setupNoRestakingStrategyRoles() internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IPufferStrategy.callStake.selector;

        accessManager.setTargetFunctionRole(noRestakingStrategy, selectors, ROLE_ID_PUFFER_PROTOCOL);

        bytes4[] memory selectorsForGuardians = new bytes4[](1);
        selectorsForGuardians[0] = bytes4(hex"abfaad62"); // signature for `function postRewardsRoot(bytes32 root, uint256 blockNumber)`
        accessManager.setTargetFunctionRole(noRestakingStrategy, selectorsForGuardians, ROLE_ID_GUARDIANS);
    }

    function _setupEnclaveVerifierRoles() internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EnclaveVerifier.removeLeafX509.selector;

        accessManager.setTargetFunctionRole(enclaveVerifier, selectors, ROLE_ID_DAO);
    }

    function _setupPufferProtocolRoles() internal {
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

        accessManager.setTargetFunctionRole(address(pufferProtocol), selectors, ROLE_ID_DAO);

        bytes4[] memory guardianSelectors = new bytes4[](3);
        guardianSelectors[0] = PufferProtocol.skipProvisioning.selector;
        guardianSelectors[1] = PufferProtocol.stopValidator.selector;
        guardianSelectors[2] = PufferProtocol.proofOfReserve.selector;
        accessManager.setTargetFunctionRole(address(pufferProtocol), guardianSelectors, ROLE_ID_GUARDIANS);
    }

    function _grantRoles(address DAO) internal {
        accessManager.grantRole(ROLE_ID_DAO, DAO, 0);

        accessManager.grantRole(ROLE_ID_GUARDIANS, guardians, 0);

        accessManager.grantRole(ROLE_ID_PUFFER_PROTOCOL, pufferProtocol, 0);
    }
}
