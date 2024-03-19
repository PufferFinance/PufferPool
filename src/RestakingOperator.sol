// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { Initializable } from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { IRestakingOperator } from "puffer/interface/IRestakingOperator.sol";
import { Unauthorized, InvalidAddress } from "puffer/Errors.sol";
import { IPufferModuleManager } from "puffer/interface/IPufferModuleManager.sol";

/**
 * @title RestakingOperator
 * @author Puffer Finance
 * @notice PufferModule
 * @custom:security-contact security@puffer.fi
 */
contract RestakingOperator is IRestakingOperator, Initializable, AccessManagedUpgradeable {
    // keccak256(abi.encode(uint256(keccak256("RestakingOperator.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _RESTAKING_OPERATOR_STORAGE =
        0x2182a68f8e463a6b4c76f5de5bb25b7b51ccc88cb3b9ba6c251c356b50555100;

    /**
     * @custom:storage-location erc7201:RestakingOperator.storage
     * @dev +-----------------------------------------------------------+
     *      |                                                           |
     *      | DO NOT CHANGE, REORDER, REMOVE EXISTING STORAGE VARIABLES |
     *      |                                                           |
     *      +-----------------------------------------------------------+
     */
    // struct RestakingOperatorStorage { }

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    IDelegationManager public immutable override EIGEN_DELEGATION_MANAGER;

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    ISlasher public immutable override EIGEN_SLASHER;

    /**
     * @dev Upgradeable Puffer Module Manager
     */
    IPufferModuleManager public immutable PUFFER_MODULE_MANAGER;

    modifier onlyPufferModuleManager() {
        if (msg.sender != address(PUFFER_MODULE_MANAGER)) {
            revert Unauthorized();
        }
        _;
    }

    // We use constructor to set the immutable variables
    constructor(IDelegationManager delegationManager, ISlasher slasher, IPufferModuleManager moduleManager) {
        if (address(delegationManager) == address(0)) {
            revert InvalidAddress();
        }
        if (address(slasher) == address(0)) {
            revert InvalidAddress();
        }
        if (address(moduleManager) == address(0)) {
            revert InvalidAddress();
        }
        EIGEN_DELEGATION_MANAGER = delegationManager;
        EIGEN_SLASHER = slasher;
        PUFFER_MODULE_MANAGER = moduleManager;
    }

    function initialize(
        address initialAuthority,
        IDelegationManager.OperatorDetails calldata operatorDetails,
        string calldata metadataURI
    ) external initializer {
        __AccessManaged_init(initialAuthority);
        EIGEN_DELEGATION_MANAGER.registerAsOperator(operatorDetails, metadataURI);
    }

    /**
     * @inheritdoc IRestakingOperator
     * @dev Restricted to the PufferModuleManager
     */
    function optIntoSlashing(address slasher) external virtual onlyPufferModuleManager {
        EIGEN_SLASHER.optIntoSlashing(slasher);
    }

    /**
     * @inheritdoc IRestakingOperator
     * @dev Restricted to the PufferModuleManager
     */
    function modifyOperatorDetails(IDelegationManager.OperatorDetails calldata newOperatorDetails)
        external
        virtual
        onlyPufferModuleManager
    {
        EIGEN_DELEGATION_MANAGER.modifyOperatorDetails(newOperatorDetails);
    }

    // function _getRestakingOperatorStorage() internal pure returns (RestakingOperatorStorage storage $) {
    //     // solhint-disable-next-line
    //     assembly {
    //         $.slot := _RESTAKING_OPERATOR_STORAGE
    //     }
    // }
}
