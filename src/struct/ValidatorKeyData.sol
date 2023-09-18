// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";

/**
 * @dev Validator Key data struct
 */
struct ValidatorKeyData {
    bytes blsPubKey;
    bytes signature;
    bytes32 depositDataRoot;
    bytes[] blsEncryptedPrivKeyShares;
    bytes[] blsPubKeyShares;
    uint256 blockNumber;
    RaveEvidence evidence;
}
