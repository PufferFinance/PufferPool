// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";

/**
 * @custom:storage-location erc7201:PufferProtocol.storage
 */
struct ProtocolStorage {
    /**
     * @dev Puffer Pool
     * Slot 0
     */
    IPufferPool pool;
    /**
     * @dev Withdrawal pool address
     * Slot 1
     */
    IWithdrawalPool withdrawalPool;
    /**
     * @dev Guardian module
     * Slot 2
     */
    IGuardianModule guardianModule;
    /**
     * @dev Strategy weights
     * Slot 3
     */
    bytes32[] strategyWeights;
    /**
     * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     * Slot 4
     */
    uint72 protocolFeeRate;
    /**
     * @dev WithdrawalPool rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     * Slot 4
     */
    uint72 withdrawalPoolRate;
    /**
     * @dev Guardians fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     * Slot 4
     */
    uint72 guardiansFeeRate;
    /**
     * @dev Number of validators registered in this interval
     * Slot 4
     */
    uint16 numberOfValidatorsRegisteredInThisInterval;
    /**
     * @dev Number of validators allowed per interval
     * Slot 4
     */
    uint16 validatorLimitPerInterval;
    /**
     * @dev Select strategy index
     * Slot 5
     */
    uint128 strategySelectIndex;
    /**
     * @dev Mapping of strategy name to pending validator index for that strategy
     * Slot 6
     */
    mapping(bytes32 strategyName => uint256 pendingValidatorIndex) pendingValidatorIndicies;
    /**
     * @dev Mapping of a strategy name to validator queue
     * Slot 7
     */
    mapping(bytes32 strategyName => uint256 nextInLineToBeProvisionedIndex) nextToBeProvisioned;
    /**
     * @dev Mapping of Strategy name => idx => Validator
     * Index is incrementing starting from 0, not to be mistaken with Beacon Chain Validator Index
     * Slot 8
     */
    mapping(bytes32 strategyName => mapping(uint256 index => Validator validator)) validators;
    /**
     * @dev Mapping of a blockNumber and Merkle Root for full withdrawals
     */
    mapping(uint256 blockNumber => bytes32 root) fullWithdrawalsRoots;
    /**
     * @dev Mapping between strategy name and a strategy
     * Slot 9
     */
    mapping(bytes32 strategyName => IPufferStrategy strategyAddress) strategies;
    /**
     * @dev Array of smoothing commitments for a number of months and smoothing commitment amount (in wei)
     * Slot 10
     */
    uint256[] smoothingCommitments;
}
