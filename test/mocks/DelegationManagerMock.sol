// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";

contract DelegationManagerMock {
    function registerAsOperator(
        IDelegationManager.OperatorDetails calldata registeringOperatorDetails,
        string calldata metadataURI
    ) external { }

    function modifyOperatorDetails(IDelegationManager.OperatorDetails calldata newOperatorDetails) external { }
}
