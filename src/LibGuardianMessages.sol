// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { MessageHashUtils } from "openzeppelin/utils/cryptography/MessageHashUtils.sol";

/**
 * @title LibGuardianMessages
 * @author Puffer finance
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
    function getMessageToBeSigned(
        bytes memory pubKey,
        bytes calldata signature,
        bytes calldata withdrawalCredentials,
        bytes32 depositDataRoot
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(pubKey, withdrawalCredentials, signature, depositDataRoot)).toEthSignedMessageHash();
    }

    /**
     * @notice Returns the message to be signed for skip provisioning
     * @param strategyName is the name of the strategy
     * @param index is the index of the skipped validator
     * @return the message to be signed
     */
    function getSkipProvisioningMessage(bytes32 strategyName, uint256 index) external pure returns (bytes32) {
        // All guardians use the same nonce
        return keccak256(abi.encode(strategyName, index)).toEthSignedMessageHash();
    }

    /**
     * @notice Returns the message to be signed for the no restaking strategy rewards root
     * @param strategyName is the name of the strategy
     * @param root is the root of the no restaking strategy rewards
     * @param blockNumber is the block number of the no restaking strategy rewards
     * @return the message to be signed
     */
    function getNoRestakingStrategyRewardsRootMessage(bytes32 strategyName, bytes32 root, uint256 blockNumber)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(strategyName, root, blockNumber)).toEthSignedMessageHash();
    }

    /**
     * @notice Returns the message to be signed for the proof of reserve
     * @param ethAmount is the amount of ETH in the reserve
     * @param lockedETH is the amount of locked ETH in the reserve
     * @param pufETHTotalSupply is the total supply of pufETH tokens
     * @param blockNumber is the block number of the proof of reserve
     * @return the message to be signed
     */
    function getProofOfReserveMessage(
        uint256 ethAmount,
        uint256 lockedETH,
        uint256 pufETHTotalSupply,
        uint256 blockNumber
    ) external pure returns (bytes32) {
        // All guardians use the same nonce
        return keccak256(abi.encode(ethAmount, lockedETH, pufETHTotalSupply, blockNumber)).toEthSignedMessageHash();
    }

    /**
     * @notice Returns the message to be signed for the post full withdrawals root
     * @param root is the root of the full withdrawals
     * @param blockNumber is the block number of the full withdrawals
     * @param strategies are the addresses of the strategies
     * @param amounts are the amounts of the full withdrawals
     * @return the message to be signed
     */
    function getPostFullWithdrawalsRootMessage(
        bytes32 root,
        uint256 blockNumber,
        address[] calldata strategies,
        uint256[] calldata amounts
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(root, blockNumber, strategies, amounts)).toEthSignedMessageHash();
    }
}
