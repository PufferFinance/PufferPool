// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { IRestakingOperator } from "puffer/interface/IRestakingOperator.sol";
import { RestakingOperator } from "puffer/RestakingOperator.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";

contract PufferModuleManagerIntegrationTest is IntegrationTestHelper {
    function setUp() public {
        deployContractsGoerli(10663816);
    }

    function test_create_puffer_module() public {
        vm.startPrank(DAO);
        pufferProtocol.createPufferModule(bytes32("SOME_MODULE_NAME"));
    }

    function test_opt_into_slashing() public {
        vm.startPrank(DAO);
        IRestakingOperator operator = _createRestakingOperator();

        moduleManager.callOptIntoSlashing(operator, address(1234));
    }

    function test_modify_operator() public {
        vm.startPrank(DAO);
        IRestakingOperator operator = _createRestakingOperator();

        IDelegationManager.OperatorDetails memory newOperatorDetails = IDelegationManager.OperatorDetails({
            earningsReceiver: address(this),
            delegationApprover: address(0),
            stakerOptOutWindowBlocks: 100
        });

        moduleManager.callModifyOperatorDetails({ restakingOperator: operator, newOperatorDetails: newOperatorDetails });

        IDelegationManager.OperatorDetails memory details =
            operator.EIGEN_DELEGATION_MANAGER().operatorDetails(address(operator));
        assertEq(details.stakerOptOutWindowBlocks, 100, "updated blocks");

        assertEq(details.earningsReceiver, address(this), "updated earnings");
    }

    // Creates a new restaking operator and returns it
    // metadataURI is used as seed for create2 in EL
    function _createRestakingOperator() internal returns (IRestakingOperator) {
        IRestakingOperator operator = moduleManager.createNewRestakingOperator({
            metadataURI: "https://puffer.fi/metadata.json",
            delegationApprover: address(0),
            stakerOptOutWindowBlocks: 0
        });

        IDelegationManager.OperatorDetails memory details =
            operator.EIGEN_DELEGATION_MANAGER().operatorDetails(address(operator));
        assertEq(details.delegationApprover, address(0), "delegation approver");
        assertEq(details.stakerOptOutWindowBlocks, 0, "blocks");
        assertEq(details.earningsReceiver, address(moduleManager), "earnings receiver");

        return operator;
    }
}
