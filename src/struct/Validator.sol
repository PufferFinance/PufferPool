// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Status } from "puffer/struct/Status.sol";

/**
 * @dev Validator struct
 */
struct Validator {
    address node;
    address strategy;
    uint256 pufETHBond;
    Status status;
    bytes pubKey;
}
