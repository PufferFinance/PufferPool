// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

interface IPufferAVSServiceManager {
    /// @notice Returns the 'taskNumber' for the service
    function getTask() external view returns (uint32);

    /// @notice Permissioned function allowing ServiceManager to freeze the operator on EigenLayer, through a call to the Slasher contract
    function haltOperator(address operator) external;

    /// @notice Permissioned function allowing ServiceManager to forward a call to the slasher, recording an initial stake update (on operator registration)
    function recordInitialStakeUpdate(address operator, uint32 serveUntilBlock) external;

    /// @notice Permissioned function allowing ServiceManager to forward a call to the slasher, recording a stake update
    function recordStakeUpdate(address operator, uint32 updateBlock, uint32 serveUntil, uint256 prevElement) external;

    /// @notice Permissioned function allowing ServiceManager to forward a call to the slasher, recording a final stake update (on operator deregistration)
    function recordFinalStakeUpdateRevokeSlashing(address operator, uint32 serveUntil) external;

    /// @notice Returns the latest block until which operators must serve.
    function lastServeUntilBlock() external view returns (uint32);

    function owner() external view returns (address);
}