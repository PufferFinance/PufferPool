// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Validator } from "puffer/struct/Validator.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";

/**
 * @custom:storage-location erc7201:PufferProtocol.storage
 * @dev +-----------------------------------------------------------+
 *      |                                                           |
 *      | DO NOT CHANGE, REORDER, REMOVE EXISTING STORAGE VARIABLES |
 *      |                                                           |
 *      +-----------------------------------------------------------+
 */
struct ProtocolStorage {
    /**
     * @dev Module weights
     * Slot 0
     */
    bytes32[] moduleWeights;
    /**
     * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     * Slot 1
     */
    uint72 protocolFeeRate;
    /**
     * @dev WithdrawalPool rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     * Slot 1
     */
    uint72 withdrawalPoolRate;
    /**
     * @dev Guardians fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     * Slot 1
     */
    uint72 guardiansFeeRate;
    /**
     * @dev Number of validators registered in this interval
     * Slot 1
     */
    uint16 numberOfValidatorsRegisteredInThisInterval;
    /**
     * @dev Number of validators allowed per interval
     * Slot 1
     */
    uint16 validatorLimitPerInterval;
    /**
     * @dev Number of active puffer validators
     * Slot 2
     */
    uint128 activePufferValidators;
    /**
     * @dev Total number of active validators on Beacon Chain
     * Slot 2
     */
    uint128 numberOfActiveValidators;
    /**
     * @dev Select module index
     * Slot 3
     */
    uint256 moduleSelectIndex;
    /**
     * @dev Mapping of module name to pending validator index for that module
     * Slot 4
     */
    mapping(bytes32 moduleName => uint256 pendingValidatorIndex) pendingValidatorIndices;
    /**
     * @dev Mapping of a module name to validator queue
     * Slot 5
     */
    mapping(bytes32 moduleName => uint256 nextInLineToBeProvisionedIndex) nextToBeProvisioned;
    /**
     * @dev Mapping of Module name => idx => Validator
     * Index is incrementing starting from 0, not to be mistaken with Beacon Chain Validator Index
     * Slot 6
     */
    mapping(bytes32 moduleName => mapping(uint256 index => Validator validator)) validators;
    /**
     * @dev Mapping of a blockNumber and Merkle Root for full withdrawals
     * Slot 7
     */
    mapping(uint256 blockNumber => bytes32 root) fullWithdrawalsRoots;
    /**
     * @dev Mapping between module name and a module
     * Slot 8
     */
    mapping(bytes32 moduleName => IPufferModule moduleAddress) modules;
    /**
     * @dev Array of smoothing commitments for a number of months and smoothing commitment amount (in wei)
     * Slot 9
     */
    uint256[] smoothingCommitments;
    /**
     * @dev Mapping of Module name => Module limit
     * Slot 10
     */
    mapping(bytes32 moduleName => ModuleLimit moduleLimit) moduleLimits;
}

struct ModuleLimit {
    uint128 allowedLimit;
    uint128 numberOfActiveValidators;
}
