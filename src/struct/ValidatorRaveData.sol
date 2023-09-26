// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

struct ValidatorRaveData {
    bytes pubKey;
    bytes signature;
    bytes32 depositDataRoot;
    bytes[] blsEncryptedPrivKeyShares;
    bytes[] blsPubKeyShares;
}
