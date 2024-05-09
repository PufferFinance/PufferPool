// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { Multicall } from "openzeppelin/utils/Multicall.sol";
import { console } from "forge-std/console.sol";
import { AVSContractsRegistry } from "../../src/AVSContractsRegistry.sol";
import { ROLE_ID_AVS_COORDINATOR_ALLOWLISTER, ROLE_ID_DAO } from "pufETHScript/Roles.sol";

/**
 * @title GenerateAccessManagerCalldata1
 * @author Puffer Finance
 * @notice Generates the AccessManager call data to setup the public access
 * The returned calldata is queued and executed by the Operations Multisig
 * 1. timelock.queueTransaction(address(accessManager), encodedMulticall, 1)
 * 2. ... 7 days later ...
 * 3. timelock.executeTransaction(address(accessManager), encodedMulticall, 1)
 */
contract GenerateAccessManagerCalldata1 is Script {
    function run(address avsContractsRegistry, address whitelister) public pure returns (bytes memory) {
        bytes[] memory calldatas = new bytes[](3);

        bytes4[] memory whitelisterSelectors = new bytes4[](1);
        whitelisterSelectors[0] = AVSContractsRegistry.setAvsRegistryCoordinator.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            avsContractsRegistry,
            whitelisterSelectors,
            ROLE_ID_AVS_COORDINATOR_ALLOWLISTER
        );

        // Whitelister has 1 day timelock to add new coordinators
        calldatas[1] = abi.encodeWithSelector(
            AccessManager.grantRole.selector,
            ROLE_ID_AVS_COORDINATOR_ALLOWLISTER,
            whitelister,
            1 days // 1 day timelock
        );

        // The role guardian can cancel
        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setRoleGuardian.selector, ROLE_ID_AVS_COORDINATOR_ALLOWLISTER, ROLE_ID_DAO
        );

        bytes memory encodedMulticall = abi.encodeCall(Multicall.multicall, (calldatas));

        // console.log("GenerateAccessManagerCallData:");
        // console.logBytes(encodedMulticall);

        return encodedMulticall;
    }
}
