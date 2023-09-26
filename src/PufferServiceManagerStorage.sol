// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";

/**
 * @title PufferServiceManagerStorage
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
abstract contract PufferServiceManagerStorage {
    /**
     * @dev Constant representing 100%
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * 1e18; // 1e18 = WAD

    bytes32 private constant PUFFER_SERVICE_MANAGER_STORAGE =
        0x8a621627e30e4413ec3f43697d54d247cd8f0b626fb01f95c529b13b5b511300;

    /**
     * @custom:storage-location erc7201:PufferServiceManagerStorage.storage
     */
    struct ServiceManagerStorage {
        /**
         * @notice Puffer Pool
         */
        PufferPool pool;
        /**
         * @dev Guardians multisig wallet
         */
        Safe guardians;
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
        GuardianModule guardianModule;
        /**
         * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
         */
        uint256 protocolFeeRate;
        /**
         * @dev Next validator index for provisioning queue
         */
        uint256 pendingValidatorIndex;
        /**
         * @dev Index of the validator that will be provisioned next
         */
        uint256 validatorIndexToBeProvisionedNext;
        mapping(uint256 => Validator) validators;
    }

    function _getPufferServiceManagerStorage() internal pure returns (ServiceManagerStorage storage $) {
        assembly {
            $.slot := PUFFER_SERVICE_MANAGER_STORAGE
        }
    }
}
