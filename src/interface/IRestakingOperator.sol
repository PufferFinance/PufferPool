// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";

/**
 * @title IRestakingOperator
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IRestakingOperator {
    /**
     * @notice Returns the EigenLayer's DelegationManager
     */
    function EIGEN_DELEGATION_MANAGER() external view returns (IDelegationManager);

    /**
     * @notice Returns the EigenLayer's Slasher
     */
    function EIGEN_SLASHER() external view returns (ISlasher);

    /**
     * @notice Modify the operator details
     * @param newOperatorDetails is the struct with new operator details
     * @dev Restricted to the PufferModuleManager
     */
    function modifyOperatorDetails(IDelegationManager.OperatorDetails calldata newOperatorDetails) external;

    /**
     * @notice Opts the restaking operator into slashing by the slasher
     * @param slasher is the address of the slasher contract to opt into
     * @dev Restricted to the PufferModuleManager
     */
    function optIntoSlashing(address slasher) external;
}
