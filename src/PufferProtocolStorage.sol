// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { PufferStrategy } from "puffer/PufferStrategy.sol";

/**
 * @title PufferProtocolStorage
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
abstract contract PufferProtocolStorage {
    /**
     * @dev Constant representing 100%
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * 1e18; // 1e18 = WAD

    uint256 public constant BURST_THRESHOLD = 20;

    bytes32 private constant PUFFER_PROTOCOL_STORAGE =
        0xb8d3716136db480afe9a80da6be84f994509ecf9515ed14d03024589b5f2bd00;

    /**
     * @custom:storage-location erc7201:PufferProtocol.storage
     */
    struct ProtocolStorage {
        /**
         * @notice Puffer Pool
         */
        PufferPool pool;
        /**
         * @dev Guardians multisig wallet
         */
        Safe guardians;
        /**
         * @dev Default strategy
         */
        PufferStrategy noRestakingStrategy;
        /**
         * @dev Consensus rewards and withdrawals pool address
         */
        address withdrawalPool;
        /**
         * @dev Execution rewards vault's address
         */
        address executionRewardsVault;
        /**
         * @dev Vault for handling consensus rewards and withdrawals
         */
        address consensusVault;
        /**
         * @dev Contract responsible for RAVE attestation
         */
        IEnclaveVerifier enclaveVerifier;
        /**
         * @dev Consensus rewards commission, can be updated by governance (1e20 = 100%, 1e18 = 1%)
         */
        uint256 consensusCommission;
        /**
         * @dev Execution rewards, can be updated by governance (1e20 = 100%, 1e18 = 1%)
         */
        uint256 executionCommission;
        /**
         * @dev Guardian module
         */
        GuardianModule guardianModule;
        /**
         * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
         */
        uint256 protocolFeeRate;
        /**
         * @dev Execution rewards commitment amount (in wei)
         */
        uint256 executionRewardsCommitment;
        /**
         * @dev Next validator index for provisioning queue
         */
        uint256 pendingValidatorIndex;
        /**
         * @dev Index of the validator that will be provisioned next
         */
        uint256 validatorIndexToBeProvisionedNext;
        mapping(uint256 => Validator) validators;
        /**
         * Mapping representing Strategies
         */
        mapping(bytes32 => PufferStrategy) strategies;
    }

    function _getPufferProtocolStorage() internal pure returns (ProtocolStorage storage $) {
        assembly {
            $.slot := PUFFER_PROTOCOL_STORAGE
        }
    }
}
