// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

interface IPufferAVSRegistry {
    /// @notice Returns True if the `operator` is "registered" and thus an active operator
    function operatorActive(address operator) external view returns (bool);

    /// @notice Registers an operator
    function registerOperator(bytes calldata registrationData) external;

    /// @notice Deregisters an operator
    function deregisterOperator(bytes calldata deregistrationData) external;
}