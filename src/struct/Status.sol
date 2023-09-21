// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @dev Validator Status
 */
enum Status {
    INACTIVE,
    PREREGISTRATION,
    PENDING,
    ACTIVE,
    FROZEN,
    EXITED
}
