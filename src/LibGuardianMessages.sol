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
     * @param signature is the BLS signature of the deposit data
     * @param withdrawalCredentials are the withdrawal credentials for this validator
     * @param depositDataRoot is the hash of the deposit data
     * @return hash of the data
     */
    function _getBeaconDepositMessageToBeSigned(
        bytes memory pubKey,
        bytes memory signature,
        bytes memory withdrawalCredentials,
        bytes32 depositDataRoot
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(pubKey, withdrawalCredentials, signature, depositDataRoot)).toEthSignedMessageHash();
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
     * @param ethAmount is the amount of ETH in the reserve
     * @param lockedETH is the amount of locked ETH in the reserve
     * @param pufETHTotalSupply is the total supply of pufETH tokens
     * @param blockNumber is the block number of the proof of reserve
     * @param numberOfActiveValidators is the number of all active validators on Beacon Chain
     * @return the message to be signed
     */
    function _getProofOfReserveMessage(
        uint256 ethAmount,
        uint256 lockedETH,
        uint256 pufETHTotalSupply,
        uint256 blockNumber,
        uint256 numberOfActiveValidators
    ) internal pure returns (bytes32) {
        // All guardians use the same nonce
        //solhint-disable-next-line func-named-parameters
        return keccak256(abi.encode(ethAmount, lockedETH, pufETHTotalSupply, blockNumber, numberOfActiveValidators))
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
