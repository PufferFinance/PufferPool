// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";

contract DelegationManagerMock {
    function registerAsOperator(
        IDelegationManager.OperatorDetails calldata registeringOperatorDetails,
        string calldata metadataURI
    ) external { }

    function modifyOperatorDetails(IDelegationManager.OperatorDetails calldata newOperatorDetails) external { }

    function undelegate(address staker) external returns (bytes32[] memory withdrawalRoots) { }

    function delegateTo(
        address operator,
        ISignatureUtils.SignatureWithExpiry memory approverSignatureAndExpiry,
        bytes32 approverSalt
    ) external { }

    function operatorDetails(address operator) external view returns (IDelegationManager.OperatorDetails memory) { }
}
