// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @dev Stopped validator info
 */
struct StoppedValidatorInfo {
    /// @dev Name of the module where the validator was participating.
    bytes32 moduleName;
    /// @dev Index of the validator in the module's validator list.
    uint256 validatorIndex;
    /// @dev Block number at which the validator was stopped.
    uint256 blockNumber;
    /// @dev Amount of funds withdrawn upon validator stoppage.
    uint256 withdrawalAmount;
    /// @dev Indicates whether the validator was slashed before stopping.
    bool wasSlashed;
    /// @dev Timestamp when the validator was stopped.
    uint256 validatorStopTimestamp;
}
