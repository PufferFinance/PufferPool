// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { console } from "forge-std/console.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { Multicall } from "openzeppelin/utils/Multicall.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { OperationsCoordinator } from "puffer/OperationsCoordinator.sol";
import { GenerateAccessManagerCallData } from "pufETHScript/GenerateAccessManagerCallData.sol";
import {
    ROLE_ID_OPERATIONS_MULTISIG,
    ROLE_ID_OPERATIONS_PAYMASTER,
    ROLE_ID_PUFFER_PROTOCOL,
    ROLE_ID_DAO,
    ROLE_ID_OPERATIONS_COORDINATOR
} from "pufETHScript/Roles.sol";

contract GenerateOracleCalldata is BaseScript {
    AccessManager internal accessManager;

    address pufferOracle = address(1234); //@todo <------------------------------------------------------------------------------------------------------------------------------
    address operationsCoordinator = address(555); //@todo <------------------------------------------------------------------------------------------------------------------------------

    function run() external broadcast {
        accessManager = AccessManager(payable(0x8c1686069474410E6243425f4a10177a94EBEE11));

        bytes[] memory calldatas = _generateAccessCalldata({
            pufferOracleAccess: _setupPufferOracleAccess(),
            coordinatorAccess: _setupCoordinatorAccess()
        });

        bytes memory multicallData = abi.encodeCall(Multicall.multicall, (calldatas));
        console.logBytes(multicallData);
    }

    function _generateAccessCalldata(
        bytes[] memory pufferOracleAccess,
        bytes[] memory coordinatorAccess
    ) internal view returns (bytes[] memory calldatas) {


        calldatas = new bytes[](5);
        calldatas[0] = pufferOracleAccess[0];
        calldatas[1] = pufferOracleAccess[1];
        calldatas[2] = pufferOracleAccess[2];
        calldatas[3] = coordinatorAccess[0];
        calldatas[4] = coordinatorAccess[1];
    }

    function _setupPufferOracleAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](3);

        // Only for PufferProtocol
        bytes4[] memory protocolSelectors = new bytes4[](2);
        protocolSelectors[0] = PufferOracleV2.provisionNode.selector;
        protocolSelectors[1] = PufferOracleV2.exitValidators.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferOracle,
            protocolSelectors,
            ROLE_ID_PUFFER_PROTOCOL
        );

        bytes4[] memory operationsSelectors = new bytes4[](1);
        operationsSelectors[0] = PufferOracleV2.setTotalNumberOfValidators.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferOracle,
            operationsSelectors,
            ROLE_ID_OPERATIONS_MULTISIG
        );

        bytes4[] memory coordinatorSelectors = new bytes4[](1);
        coordinatorSelectors[0] = PufferOracleV2.setMintPrice.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            pufferOracle,
            coordinatorSelectors,
            ROLE_ID_OPERATIONS_COORDINATOR
        );

        return calldatas;
    }

    function _setupCoordinatorAccess() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        bytes4[] memory operationsSelectors = new bytes4[](1);
        operationsSelectors[0] = OperationsCoordinator.setPriceChangeToleranceBps.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            operationsCoordinator,
            operationsSelectors,
            ROLE_ID_OPERATIONS_MULTISIG
        );

        bytes4[] memory paymasterSelectors = new bytes4[](1);
        paymasterSelectors[0] = OperationsCoordinator.setValidatorTicketMintPrice.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            operationsCoordinator,
            paymasterSelectors,
            ROLE_ID_OPERATIONS_PAYMASTER
        );

        return calldatas;
    }
}
