// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { PufferStrategy } from "puffer/PufferStrategy.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";

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

    bytes32 private constant PUFFER_POOL_STORAGE = 0x3d9197675aec7b7f62441149aba7986872b7337d003616efa547249bb6c43900;

    //@audit optimize storage struct
    /**
     * @custom:storage-location erc7201:PufferProtocol.storage
     */
    struct ProtocolStorage {
        /**
         * @notice Puffer Pool
         */
        PufferPool pool;
        /**
         * @dev Default strategy
         */
        PufferStrategy noRestakingStrategy;
        /**
         * @dev Withdrawal pool address
         */
        address withdrawalPool;
        /**
         * @dev Guardian module
         */
        GuardianModule guardianModule;
        /**
         * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
         */
        uint256 protocolFeeRate;
        /**
         * @dev WithdrawalPool rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
         */
        uint256 withdrawalPoolRate;
        /**
         * @dev Guardians fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
         */
        uint256 guardiansFeeRate;
        /**
         * @dev Smoothing commitment amount (in wei)
         */
        uint256 smoothingCommitment;
        /**
         * @dev Next validator index for provisioning queue
         */
        uint256 pendingValidatorIndex;
        /**
         * @dev Index of the validator that will be provisioned next
         */
        uint256 validatorIndexToBeProvisionedNext;
        /**
         * @dev Mapping of idx => Validator
         * Index is incrementing starting from 0
         */
        mapping(uint256 => Validator) validators;
        /**
         * Mapping representing Strategies
         */
        mapping(bytes32 => PufferStrategy) strategies;
    }

    struct PufferPoolStorage {
        /**
         * @dev Unlocked ETH amount
         */
        uint256 ethAmount;
        /**
         * @dev Locked ETH amount in Beacon Chain
         */
        uint256 lockedETH;
        /**
         * @dev pufETH total token supply
         */
        uint256 pufETHTotalSupply;
        /**
         * @dev Block number for when the values were updated
         */
        uint256 lastUpdate;
    }

    function getPuferPoolStorage() external pure returns (PufferPoolStorage memory) {
        PufferPoolStorage storage $;
        assembly {
            $.slot := PUFFER_POOL_STORAGE
        }

        return $;
    }

    function _getPuferPoolStorage() internal pure returns (PufferPoolStorage storage $) {
        assembly {
            $.slot := PUFFER_POOL_STORAGE
        }
    }

    function _getPufferProtocolStorage() internal pure returns (ProtocolStorage storage $) {
        assembly {
            $.slot := PUFFER_PROTOCOL_STORAGE
        }
    }
}
