// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Status } from "puffer/struct/Status.sol";

/**
 * @dev Validator struct
 */
struct Validator {
    address node; // Address of the Node operator
    address strategy; // In which strategy is the Validator participating
    uint40 commitmentExpiration; // Date when the smoothing commitment ends
    uint256 bond; // Validator bond (in pufETH)
    Status status; // Validator status
    bytes pubKey; // Validator public key
    bytes signature; // Signature of deposit data
}
