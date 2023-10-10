// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Status } from "puffer/struct/Status.sol";

/**
 * @dev Validator struct
 */
struct Validator {
    address node; // Address of the Node operator
    address strategy; // In which strategy is the Validator participating
    uint72 commitmentAmount; // Last commitment amount (uint72 max value is 4722 ETH)
    uint40 lastCommitmentPayment; // Date when the last commitment was paid
    Status status; // Validator status
    bytes pubKey; // Validator public key
    bytes signature; // Signature of deposit data
}
