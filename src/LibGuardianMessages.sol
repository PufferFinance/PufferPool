// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { MessageHashUtils } from "openzeppelin/utils/cryptography/MessageHashUtils.sol";

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
        //solhint-disable-next-line func-named-parameters
        return keccak256(abi.encode(validatorIndex, pubKey, withdrawalCredentials, signature, depositDataRoot))
            .toEthSignedMessageHash();
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
     * @notice Returns the message to be signed for the proof of reserve
     * @param lockedETH is the amount of locked ETH in the reserve
     * @param blockNumber is the block number of the proof of reserve
     * @param numberOfActivePufferValidators is the number of active Puffer Validators
     * @param totalNumberOfValidators is the number of total Validators
     * @return the message to be signed
     */
    function _getProofOfReserveMessage(
        uint256 lockedETH,
        uint256 blockNumber,
        uint256 numberOfActivePufferValidators,
        uint256 totalNumberOfValidators
    ) internal pure returns (bytes32) {
        // All guardians use the same nonce
        //solhint-disable-next-line func-named-parameters
        return keccak256(abi.encode(lockedETH, blockNumber, numberOfActivePufferValidators, totalNumberOfValidators))
            .toEthSignedMessageHash();
    }

    /**
     * @notice Returns the message to be signed for the post full withdrawals root
     * @param root is the root of the full withdrawals
     * @param blockNumber is the block number of the full withdrawals
     * @param modules are the addresses of the modules
     * @param amounts are the amounts of the full withdrawals
     * @return the message to be signed
     */
    function _getPostFullWithdrawalsRootMessage(
        bytes32 root,
        uint256 blockNumber,
        address[] memory modules,
        uint256[] memory amounts
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(root, blockNumber, modules, amounts)).toEthSignedMessageHash();
    }
}
