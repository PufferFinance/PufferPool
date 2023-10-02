// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Status } from "puffer/struct/Status.sol";

/**
 * @dev Validator struct
 */
struct Validator {
    address node; // Address of the Node operator
    address strategy; // In which strategy is the Validator participating
    uint256 commitmentAmount; // Last commitment amount
    uint256 date; // Date when the last commitment was paid
    Status status; // Validator status
    bytes pubKey; // Validator public key
}
