// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @dev AVS Parameters
 */
struct AVSParams {
    uint256 podAVSCommission;
    uint256 minReputationScore; // experimental... TODO: figure out
    uint8 minBondRequirement;
    bool enabled;
}
