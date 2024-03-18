// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { IRestakingOperator } from "puffer/interface/IRestakingOperator.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { RestakingOperator } from "puffer/RestakingOperator.sol";
import { IPufferModuleManager } from "puffer/interface/IPufferModuleManager.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { Create2 } from "openzeppelin/utils/Create2.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";

/**
 * @title PufferModuleManager
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferModuleManager is IPufferModuleManager, AccessManagedUpgradeable, UUPSUpgradeable {
    /**
     * @notice Address of the PufferModule proxy beacon
     */
    address public immutable PUFFER_MODULE_BEACON;

    /**
     * @notice Address of the Restaking operator proxy beacon
     */
    address public immutable RESTAKING_OPERATOR_BEACON;

    /**
     * @notice Address of the Puffer Protocol
     */
    address public immutable PUFFER_PROTOCOL;

    constructor(address pufferModuleBeacon, address restakingOperatorBeacon, address pufferProtocol) {
        PUFFER_MODULE_BEACON = pufferModuleBeacon;
        RESTAKING_OPERATOR_BEACON = restakingOperatorBeacon;
        PUFFER_PROTOCOL = pufferProtocol;
    }

    /**
     * @notice Initializes the contract
     */
    function initialize(address accessManager) external initializer {
        __AccessManaged_init(accessManager);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the PufferProtocol
     * @param moduleName The name of the module
     */
    function createNewPufferModule(bytes32 moduleName) external returns (IPufferModule) {
        if (msg.sender != PUFFER_PROTOCOL) {
            revert Unauthorized();
        }

        return IPufferModule(
            Create2.deploy({
                amount: 0,
                salt: moduleName,
                bytecode: abi.encodePacked(
                    type(BeaconProxy).creationCode,
                    abi.encode(
                        PUFFER_MODULE_BEACON, abi.encodeCall(PufferModule.initialize, (moduleName, authority(), this))
                    )
                    )
            })
        );
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the DAO
     */
    function createNewRestakingOperator(
        string calldata metadataURI,
        address delegationApprover,
        uint32 stakerOptOutWindowBlocks
    ) external restricted returns (IRestakingOperator) {
        IDelegationManager.OperatorDetails memory operatorDetails = IDelegationManager.OperatorDetails({
            earningsReceiver: address(this),
            delegationApprover: delegationApprover,
            stakerOptOutWindowBlocks: stakerOptOutWindowBlocks
        });

        return IRestakingOperator(
            Create2.deploy({
                amount: 0,
                salt: keccak256(abi.encode(metadataURI)),
                bytecode: abi.encodePacked(
                    type(BeaconProxy).creationCode,
                    abi.encode(
                        RESTAKING_OPERATOR_BEACON,
                        abi.encodeCall(
                            RestakingOperator.initialize, (authority(), address(this), operatorDetails, metadataURI)
                        )
                    )
                    )
            })
        );
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the DAO
     */
    function callModifyOperatorDetails(
        IRestakingOperator restakingOperator,
        IDelegationManager.OperatorDetails calldata newOperatorDetails
    ) external restricted {
        restakingOperator.modifyOperatorDetails(newOperatorDetails);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the DAO
     */
    function callOptIntoSlashing(IRestakingOperator restakingOperator, address slasher) external restricted {
        restakingOperator.optIntoSlashing(slasher);
        emit RestakingOperatorOptedInSlasher(address(restakingOperator), slasher);
    }

    function callDelegateToBySignature(IPufferModule module) external { }
    function callUndelegate(IPufferModule module) external { }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
