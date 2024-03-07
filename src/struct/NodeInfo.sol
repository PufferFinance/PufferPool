// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @dev Everything is packed in 1 storage slot
 */
struct NodeInfo {
    uint16 activeValidatorCount;
    uint8 pendingValidatorCount;
    uint48 lastUpdate;
    uint96 vtBalance;
    uint88 virtualVTBalance;
    uint256 bond;
}
