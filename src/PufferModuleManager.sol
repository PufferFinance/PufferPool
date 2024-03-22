// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { IRestakingOperator } from "puffer/interface/IRestakingOperator.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { RestakingOperator } from "puffer/RestakingOperator.sol";
import { IPufferModuleManager } from "puffer/interface/IPufferModuleManager.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { Create2 } from "openzeppelin/utils/Create2.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";
import { IERC20 } from "openzeppelin/token/ERC20/IERC20.sol";

/**
 * @title PufferModuleManager
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferModuleManager is IPufferModuleManager, AccessManagedUpgradeable, UUPSUpgradeable {
    /**
     * @inheritdoc IPufferModuleManager
     */
    address public immutable override PUFFER_MODULE_BEACON;

    /**
     * @inheritdoc IPufferModuleManager
     */
    address public immutable override RESTAKING_OPERATOR_BEACON;

    /**
     * @inheritdoc IPufferModuleManager
     */
    address public immutable override PUFFER_PROTOCOL;

    modifier onlyPufferProtocol() {
        if (msg.sender != PUFFER_PROTOCOL) {
            revert Unauthorized();
        }
        _;
    }

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
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function callVerifyWithdrawalCredentials(
        bytes32 moduleName,
        uint64 oracleTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        uint40[] calldata validatorIndices,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields
    ) external virtual restricted {
        address moduleAddress = IPufferProtocol(PUFFER_PROTOCOL).getModuleAddress(moduleName);

        IPufferModule(moduleAddress).verifyWithdrawalCredentials({
            oracleTimestamp: oracleTimestamp,
            stateRootProof: stateRootProof,
            validatorIndices: validatorIndices,
            validatorFieldsProofs: validatorFieldsProofs,
            validatorFields: validatorFields
        });

        emit ValidatorCredentialsVerified(moduleName, validatorIndices);
    }

    /**
     * @notice Completes queued withdrawals
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function callCompleteQueuedWithdrawals(
        bytes32 moduleName,
        IDelegationManager.Withdrawal[] calldata withdrawals,
        IERC20[][] calldata tokens,
        uint256[] calldata middlewareTimesIndexes
    ) external virtual restricted {
        address moduleAddress = IPufferProtocol(PUFFER_PROTOCOL).getModuleAddress(moduleName);

        IPufferModule(moduleAddress).completeQueuedWithdrawals(withdrawals, tokens, middlewareTimesIndexes);

        //@todo figure out the event
        emit CompleteQueuedWithdrawals(moduleName, 0);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the PufferProtocol
     * @param moduleName The name of the module
     */
    function createNewPufferModule(bytes32 moduleName) external virtual onlyPufferProtocol returns (IPufferModule) {
        // This called from the PufferProtocol and the event is emitted there
        return IPufferModule(
            Create2.deploy({
                amount: 0,
                salt: moduleName,
                bytecode: abi.encodePacked(
                    type(BeaconProxy).creationCode,
                    abi.encode(PUFFER_MODULE_BEACON, abi.encodeCall(PufferModule.initialize, (moduleName, authority())))
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
    ) external virtual restricted returns (IRestakingOperator) {
        IDelegationManager.OperatorDetails memory operatorDetails = IDelegationManager.OperatorDetails({
            earningsReceiver: address(this),
            delegationApprover: delegationApprover,
            stakerOptOutWindowBlocks: stakerOptOutWindowBlocks
        });

        address restakingOperator = Create2.deploy({
            amount: 0,
            salt: keccak256(abi.encode(metadataURI)),
            bytecode: abi.encodePacked(
                type(BeaconProxy).creationCode,
                abi.encode(
                    RESTAKING_OPERATOR_BEACON,
                    abi.encodeCall(RestakingOperator.initialize, (authority(), operatorDetails, metadataURI))
                )
                )
        });

        emit RestakingOperatorCreated(restakingOperator, operatorDetails);

        return IRestakingOperator(restakingOperator);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the DAO
     */
    function callModifyOperatorDetails(
        IRestakingOperator restakingOperator,
        IDelegationManager.OperatorDetails calldata newOperatorDetails
    ) external virtual restricted {
        restakingOperator.modifyOperatorDetails(newOperatorDetails);
        emit RestakingOperatorModified(address(restakingOperator), newOperatorDetails);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the DAO
     */
    function callUpdateMetadataURI(IRestakingOperator restakingOperator, string calldata metadataURI)
        external
        virtual
        restricted
    {
        restakingOperator.updateOperatorMetadataURI(metadataURI);
        emit RestakingOperatorMetadataURIUpdated(address(restakingOperator), metadataURI);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the DAO
     */
    function callOptIntoSlashing(IRestakingOperator restakingOperator, address slasher) external virtual restricted {
        restakingOperator.optIntoSlashing(slasher);
        emit RestakingOperatorOptedInSlasher(address(restakingOperator), slasher);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to PufferBot
     */
    function callVerifyAndProcessWithdrawals(
        bytes32 moduleName,
        uint64 oracleTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        BeaconChainProofs.WithdrawalProof[] calldata withdrawalProofs,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields,
        bytes32[][] calldata withdrawalFields
    ) external virtual restricted {
        address moduleAddress = IPufferProtocol(PUFFER_PROTOCOL).getModuleAddress(moduleName);

        IPufferModule(moduleAddress).verifyAndProcessWithdrawals({
            oracleTimestamp: oracleTimestamp,
            stateRootProof: stateRootProof,
            withdrawalProofs: withdrawalProofs,
            validatorFieldsProofs: validatorFieldsProofs,
            validatorFields: validatorFields,
            withdrawalFields: withdrawalFields
        });

        emit VerifyAndProcessWithdrawals(moduleName, validatorFields, withdrawalFields);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to PufferBot
     */
    function callWithdrawNonBeaconChainETHBalanceWei(bytes32 moduleName, uint256 amountToWithdraw)
        external
        virtual
        restricted
    {
        address moduleAddress = IPufferProtocol(PUFFER_PROTOCOL).getModuleAddress(moduleName);

        IPufferModule(moduleAddress).withdrawNonBeaconChainETHBalanceWei(amountToWithdraw);

        emit NonBeaconChainETHBalanceWithdrawn(moduleName, amountToWithdraw);
    }

    /**
     * @inheritdoc IPufferModuleManager
     */
    function callQueueWithdrawals(bytes32 moduleName, uint256 sharesAmount) external virtual restricted {
        address moduleAddress = IPufferProtocol(PUFFER_PROTOCOL).getModuleAddress(moduleName);
        IPufferModule(moduleAddress).queueWithdrawals(sharesAmount);
        emit WithdrawalsQueued(moduleName, sharesAmount);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the DAO
     */
    function callDelegateTo(
        bytes32 moduleName,
        address operator,
        ISignatureUtils.SignatureWithExpiry calldata approverSignatureAndExpiry,
        bytes32 approverSalt
    ) external virtual restricted {
        address moduleAddress = IPufferProtocol(PUFFER_PROTOCOL).getModuleAddress(moduleName);

        IPufferModule(moduleAddress).callDelegateTo(operator, approverSignatureAndExpiry, approverSalt);

        emit PufferModuleDelegated(moduleName, operator);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the DAO
     */
    function callUndelegate(bytes32 moduleName) external virtual restricted returns (bytes32[] memory withdrawalRoot) {
        address moduleAddress = IPufferProtocol(PUFFER_PROTOCOL).getModuleAddress(moduleName);

        withdrawalRoot = IPufferModule(moduleAddress).callUndelegate();

        emit PufferModuleUndelegated(moduleName);
    }

    /**
     * @inheritdoc IPufferModuleManager
     * @dev Restricted to the DAO
     */
    function updateAVSRegistrationSignatureProof(
        IRestakingOperator restakingOperator,
        bytes32 digestHash,
        address signer
    ) external virtual restricted {
        restakingOperator.updateSignatureProof(digestHash, signer);

        emit AVSRegistrationSignatureProofUpdated(address(restakingOperator), digestHash, signer);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
