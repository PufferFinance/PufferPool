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
     * @dev Select module index
     * Slot 1
     */
    uint256 moduleSelectIndex;
    /**
     * @dev Mapping of module name to pending validator index for that module
     * Slot 2
     */
    mapping(bytes32 moduleName => uint256 pendingValidatorIndex) pendingValidatorIndices;
    /**
     * @dev Mapping of a module name to validator queue
     * Slot 3
     */
    mapping(bytes32 moduleName => uint256 nextInLineToBeProvisionedIndex) nextToBeProvisioned;
    /**
     * @dev Mapping of Module name => idx => Validator
     * Index is incrementing starting from 0, not to be mistaken with Beacon Chain Validator Index
     * Slot 4
     */
    mapping(bytes32 moduleName => mapping(uint256 index => Validator validator)) validators;
    /**
     * @dev Mapping of a blockNumber and Merkle Root for full withdrawals
     * Slot 5
     */
    mapping(uint256 blockNumber => bytes32 root) fullWithdrawalsRoots;
    /**
     * @dev Mapping between module name and a module
     * Slot 6
     */
    mapping(bytes32 moduleName => IPufferModule moduleAddress) modules;
    /**
     * @dev Array of smoothing commitments for a number of months and smoothing commitment amount (in wei)
     * Slot 7
     */
    uint256[] smoothingCommitments;
    /**
     * @dev Mapping of Module name => Module limit
     * Slot 8
     */
    mapping(bytes32 moduleName => ModuleLimit moduleLimit) moduleLimits;
    /**
     * @dev Mapping of Node operator address => Node operator information
     * Slot 9
     */
    mapping(address node => NodeInfo info) vtBalances;
}

struct NodeInfo {
    uint128 validatorCount;
    uint128 vtBalance;
}

struct ModuleLimit {
    uint128 allowedLimit;
    uint128 numberOfActiveValidators;
}
