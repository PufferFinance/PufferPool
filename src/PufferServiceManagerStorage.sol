// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";

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

    /**
     * @dev Consensus rewards and withdrawals pool address
     */
    address internal _withdrawalPool;

    /**
     * @dev Execution rewards vault's address
     */
    address internal _executionRewardsVault;

    /**
     * @dev Vault for handling consensus rewards and withdrawals
     */
    address internal _consensusVault;

    /**
     * @dev Contract responsible for RAVE attestation
     */
    IEnclaveVerifier internal _enclaveVerifier;

    /**
     * @dev Consensus rewards commission, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     */
    uint256 internal _consensusCommission;

    /**
     * @dev Execution rewards, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     */
    uint256 internal _executionCommission;

    GuardianModule internal _guardianModule;

    /**
     * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     */
    uint256 internal _protocolFeeRate;

    bytes32 internal _mrenclave;
    bytes32 internal _mrsigner;
    bytes32 internal _guardianMrenclave;
    bytes32 internal _guardianMrsigner;

    /**
     * @dev Next validator index for provisioning queue
     */
    uint256 pendingValidatorIndex;

    /**
     * @dev Index of the validator that will be provisioned next
     */
    uint256 validatorIndexToBeProvisionedNext;

    mapping(uint256 => Validator) internal _validators;

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
