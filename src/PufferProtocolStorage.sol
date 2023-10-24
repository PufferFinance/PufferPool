// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Validator } from "puffer/struct/Validator.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";

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

    /**
     * @dev Storage slot location for PufferProtocol
     * @custom:storage-location erc7201:PufferProtocol.storage
     */
    bytes32 private constant PUFFER_PROTOCOL_STORAGE =
        0xb8d3716136db480afe9a80da6be84f994509ecf9515ed14d03024589b5f2bd00;

    /**
     * @dev Storage slot location for PufferPool
     * @custom:storage-location erc7201:PufferPool.storage
     */
    bytes32 private constant PUFFER_POOL_STORAGE = 0x3d9197675aec7b7f62441149aba7986872b7337d003616efa547249bb6c43900;

    /**
     * @custom:storage-location erc7201:PufferProtocol.storage
     */
    struct ProtocolStorage {
        /**
         * @dev Puffer Pool
         * Slot 0
         */
        PufferPool pool;
        /**
         * @dev Withdrawal pool address
         * Slot 1
         */
        WithdrawalPool withdrawalPool;
        /**
         * @dev Guardian module
         * Slot 2
         */
        GuardianModule guardianModule;
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

    /**
     * @custom:storage-location erc7201:PufferPoolStorage.storage
     */
    struct PufferPoolStorage {
        /**
         * @dev Unlocked ETH amount
         * Slot 0
         */
        uint256 ethAmount;
        /**
         * @dev Locked ETH amount in Beacon Chain
         * Slot 1
         */
        uint256 lockedETH;
        /**
         * @dev pufETH total token supply
         * Slot 2
         */
        uint256 pufETHTotalSupply;
        /**
         * @dev Block number for when the values were updated
         * Slot 3
         */
        uint256 lastUpdate;
    }

    function getPuferPoolStorage() external pure returns (PufferPoolStorage memory) {
        PufferPoolStorage storage $;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := PUFFER_POOL_STORAGE
        }

        return $;
    }

    function _getPuferPoolStorage() internal pure returns (PufferPoolStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := PUFFER_POOL_STORAGE
        }
    }

    function _getPufferProtocolStorage() internal pure returns (ProtocolStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := PUFFER_PROTOCOL_STORAGE
        }
    }
}
