// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { IRestakingOperator } from "puffer/interface/IRestakingOperator.sol";
import { IPufferModuleManager } from "puffer/interface/IPufferModuleManager.sol";
import { RestakingOperator } from "puffer/RestakingOperator.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";

contract PufferModuleManagerIntegrationTest is IntegrationTestHelper {
    function setUp() public {
        deployContractsHolesky();
    }

    function test_create_puffer_module() public {
        vm.startPrank(DAO);
        pufferProtocol.createPufferModule(bytes32("SOME_MODULE_NAME"));
    }

    function test_opt_into_slashing() public {
        vm.startPrank(DAO);
        IRestakingOperator operator = _createRestakingOperator();

        address slasher = address(1235);

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.RestakingOperatorOptedInSlasher(address(operator), slasher);
        moduleManager.callOptIntoSlashing(operator, slasher);
    }

    function test_modify_operator() public {
        vm.startPrank(DAO);
        IRestakingOperator operator = _createRestakingOperator();

        IDelegationManager.OperatorDetails memory newOperatorDetails = IDelegationManager.OperatorDetails({
            earningsReceiver: address(this),
            delegationApprover: address(0),
            stakerOptOutWindowBlocks: 100
        });

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.RestakingOperatorModified(address(operator), newOperatorDetails);
        moduleManager.callModifyOperatorDetails({ restakingOperator: operator, newOperatorDetails: newOperatorDetails });

        IDelegationManager.OperatorDetails memory details =
            operator.EIGEN_DELEGATION_MANAGER().operatorDetails(address(operator));
        assertEq(details.stakerOptOutWindowBlocks, 100, "updated blocks");

        assertEq(details.earningsReceiver, address(this), "updated earnings");
    }

    function test_update_metadata_uri() public {
        vm.startPrank(DAO);
        IRestakingOperator operator = _createRestakingOperator();

        string memory newUri = "https://puffer.fi/updated.json";

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.RestakingOperatorMetadataURIUpdated(address(operator), newUri);
        moduleManager.callUpdateMetadataURI(operator, newUri);
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
