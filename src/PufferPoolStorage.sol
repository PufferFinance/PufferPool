// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { AVSParams } from "puffer/struct/AVSParams.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";

abstract contract PufferPoolStorage {
    /**
     * @dev Locked ETH amount
     */
    uint256 internal _lockedETHAmount;

    /**
     * @dev New rewards amount
     */
    uint256 internal _newETHRewardsAmount;

    /**
     * @dev Actively validated services (AVSs) configuration
     * AVS -> parameters
     */
    mapping(address => AVSParams) internal _allowedAVSs;

    /**
     * @dev Validator Index
     */
    uint256 validatorIndex;

    /**
     * @dev Address of the Puffer AVS contract
     */
    // TODO:
    // address internal _pufferAvsAddress;

    /**
     * @dev Number of shares out of one billion to split AVS rewards with the pool
     */
    uint256 internal _avsCommission;

    /**
     * @dev Number of shares out of one billion to split consensus rewards with the pool
     */
    uint256 internal _consensusCommission;

    /**
     * @dev Number of shares out of one billion to split execution rewards with the pool
     */
    uint256 internal _executionCommission;

    /**
     * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     */
    uint256 internal _protocolFeeRate;

    /**
     * @dev Validator bond for non custodial node runners
     */
    uint256 internal _nonCustodialBondRequirement;

    /**
     * @dev Validator bond for non enclave node runners
     */
    uint256 internal _nonEnclaveBondRequirement;

    /**
     * @dev Validator bond for Enclave node runners
     */
    uint256 internal _enclaveBondRequirement;

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
     * @dev Guardian {Safe} Module
     */
    GuardianModule internal _guardianModule;

    /**
     * @dev Enclave verifier smart contract
     */
    IEnclaveVerifier internal _enclaveVerifier;

    bytes32 internal _mrenclave;
    bytes32 internal _mrsigner;
    bytes32 internal _guardianMrenclave;
    bytes32 internal _guardianMrsigner;

    /**
     * @dev Public keys of the active validators
     */
    EnumerableSet.Bytes32Set internal _pubKeyHashes;

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
