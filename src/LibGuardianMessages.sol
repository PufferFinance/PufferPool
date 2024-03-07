// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { MessageHashUtils } from "openzeppelin/utils/cryptography/MessageHashUtils.sol";

/* solhint-disable func-named-parameters */

/**
 * @title LibGuardianMessages
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
library LibGuardianMessages {
    using MessageHashUtils for bytes32;

    /**
     * @notice Returns the message that the guardian's enclave needs to sign
     * @param validatorIndex is the validator index in Puffer
     * @param vtBurnOffset is an offset used such that VTs only burn after the validator is active
     * @param signature is the BLS signature of the deposit data
     * @param withdrawalCredentials are the withdrawal credentials for this validator
     * @param depositDataRoot is the hash of the deposit data
     * @return hash of the data
     */
    function _getBeaconDepositMessageToBeSigned(
        uint256 validatorIndex,
        uint256 vtBurnOffset,
        bytes memory pubKey,
        bytes memory signature,
        bytes memory withdrawalCredentials,
        bytes32 depositDataRoot
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(validatorIndex, vtBurnOffset, pubKey, withdrawalCredentials, signature, depositDataRoot)
        ).toEthSignedMessageHash();
    }

    /**
     * @notice Returns the message to be signed for skip provisioning
     * @param moduleName is the name of the module
     * @param index is the index of the skipped validator
     * @return the message to be signed
     */
    function _getSkipProvisioningMessage(bytes32 moduleName, uint256 index) internal pure returns (bytes32) {
        // All guardians use the same nonce
        return keccak256(abi.encode(moduleName, index)).toEthSignedMessageHash();
    }

    /**
     * @notice Returns the message to be signed for the no restaking module rewards root
     * @param moduleName is the name of the module
     * @param root is the root of the no restaking module rewards
     * @param blockNumber is the block number of the no restaking module rewards
     * @return the message to be signed
     */
    function _getModuleRewardsRootMessage(bytes32 moduleName, bytes32 root, uint256 blockNumber)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(moduleName, root, blockNumber)).toEthSignedMessageHash();
    }

    /**
     * @notice Returns the message to be signed for the post full withdrawals root
     * @param root is the root of the full withdrawals
     * @param blockNumber is the block number of the full withdrawals
     * @return the message to be signed
     */
    function _getPostFullWithdrawalsRootMessage(bytes32 root, uint256 blockNumber) internal pure returns (bytes32) {
        return keccak256(abi.encode(root, blockNumber)).toEthSignedMessageHash();
    }
}
/* solhint-disable func-named-parameters */
