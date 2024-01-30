// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Status } from "puffer/struct/Status.sol";

/**
 * @dev Validator struct
 */
struct Validator {
    address node; // Address of the Node operator
    address module; // In which module is the Validator participating
    uint24 daysCommitted; // Number of days the Validator has committed via locked VT
    uint64 bond; // Validator bond (in pufETH)
    Status status; // Validator status
    bytes pubKey; // Validator public key
    bytes signature; // Signature of deposit data
}
