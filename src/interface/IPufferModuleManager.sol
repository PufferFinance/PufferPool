// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { IRestakingOperator } from "puffer/interface/IRestakingOperator.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";

/**
 * @title IPufferModuleManager
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferModuleManager {
    /**
     * @notice Emitted when a Restaking Operator is opted into a slasher
     * @param restakingOperator is the address of the restaking operator
     * @param slasher is the address of the slasher contract
     * @dev Signature "0xfaf85fa92e9a913f582def722d9da998852ef6cd2fc7715266e3c3b16495c7ac"
     */
    event RestakingOperatorOptedInSlasher(address indexed restakingOperator, address indexed slasher);

    /**
     * @notice Emitted when the Restaking Operator is created
     * @param restakingOperator is the address of the restaking operator
     * @param operatorDetails is the struct with new operator details
     * @dev Signature "0xbb6c366230e589c402e164f680d07db88a6c1d4dda4dd2dcbab5528c09a6b046"
     */
    event RestakingOperatorCreated(
        address indexed restakingOperator, IDelegationManager.OperatorDetails operatorDetails
    );

    /**
     * @notice Emitted when the Restaking Operator is modified
     * @param restakingOperator is the address of the restaking operator
     * @param newOperatorDetails is the struct with new operator details
     * @dev Signature "0xee78237d6444cc6c9083c1ef31a82b0feac23fbdf0cf52d7b0ed66dfa5f7f9f2"
     */
    event RestakingOperatorModified(
        address indexed restakingOperator, IDelegationManager.OperatorDetails newOperatorDetails
    );

    /**
     * @notice Emitted when the Withdrawals are queued
     * @param moduleName is the name of the module
     * @param shareAmount is the amount of shares
     * @dev Signature "0x172c7d4f364f16dc6f7b2284cc3dc962c8f52734b13ad229c297369c05cea6bf"
     */
    event WithdrawalsQueued(bytes32 indexed moduleName, uint256 shareAmount);

    /**
     * @notice Emitted when the verify and process withdrawals is called
     * @param moduleName is the name of the module
     * @param withdrawalFields are the fields of the withdrawals being proven
     * @param validatorFields are the fields of the validators being proven
     * @dev Signature "0xa7e893f6f90b9b7358daf55bc8763c4ecc0f54366c4cf7632e9ab41da718c222"
     */
    event VerifyAndProcessWithdrawals(
        bytes32 indexed moduleName, bytes32[][] validatorFields, bytes32[][] withdrawalFields
    );

    /**
     * @notice Emitted when the Restaking Operator is updated with a new metadata URI
     * @param restakingOperator is the address of the restaking operator
     * @param metadataURI is the new URI of the operator's metadata
     * @dev Signature "0x4cb1b839d29c7a6f051ae51c7b439f2f8f991de54a4b5906503a06a0892ba2c4"
     */
    event RestakingOperatorMetadataURIUpdated(address restakingOperator, string metadataURI);

    /**
     * @notice Emitted when the Puffer Module is delegated
     * @param moduleName the module name to be delegated
     * @param operator the operator to delegate to
     */
    event PufferModuleDelegated(bytes32 indexed moduleName, address operator);

    /**
     * @notice Emitted when the Puffer Module is undelegated
     * @param moduleName the module name to be undelegated
     */
    event PufferModuleUndelegated(bytes32 indexed moduleName);

    /**
     * @notice Returns the Puffer Module beacon address
     */
    function PUFFER_MODULE_BEACON() external view returns (address);

    /**
     * @notice Returns the Restaking Operator beacon address
     */
    function RESTAKING_OPERATOR_BEACON() external view returns (address);

    /**
     * @notice Returns the Puffer Protocol address
     */
    function PUFFER_PROTOCOL() external view returns (address);

    /**
     * @notice Create a new Restaking Operator
     * @param metadataURI is a URI for the operator's metadata, i.e. a link providing more details on the operator.
     *
     * @param delegationApprover Address to verify signatures when a staker wishes to delegate to the operator, as well as controlling "forced undelegations".
     * @dev Signature verification follows these rules:
     * 1) If this address is left as address(0), then any staker will be free to delegate to the operator, i.e. no signature verification will be performed.
     * 2) If this address is an EOA (i.e. it has no code), then we follow standard ECDSA signature verification for delegations to the operator.
     * 3) If this address is a contract (i.e. it has code) then we forward a call to the contract and verify that it returns the correct EIP-1271 "magic value".
     * @return module The newly created Puffer module
     */
    function createNewRestakingOperator(
        string memory metadataURI,
        address delegationApprover,
        uint32 stakerOptOutWindowBlocks
    ) external returns (IRestakingOperator module);

    /**
     * @notice Create a new Puffer module
     * @dev This function creates a new Puffer module with the given module name
     * @param moduleName The name of the module
     * @return module The newly created Puffer module
     */
    function createNewPufferModule(bytes32 moduleName) external returns (IPufferModule module);

    /**
     * @notice Calls the modifyOperatorDetails function on the restaking operator
     * @param restakingOperator is the address of the restaking operator
     * @param newOperatorDetails is the struct with new operator details
     * @dev Restricted to the DAO
     */
    function callModifyOperatorDetails(
        IRestakingOperator restakingOperator,
        IDelegationManager.OperatorDetails calldata newOperatorDetails
    ) external;

    /**
     * @notice Calls the optIntoSlashing function on the restaking operator
     * @param restakingOperator is the address of the restaking operator
     * @param slasher is the address of the slasher contract to opt into
     * @dev Restricted to the DAO
     */
    function callOptIntoSlashing(IRestakingOperator restakingOperator, address slasher) external;

    /**
     * @notice Calls the updateOperatorMetadataURI function on the restaking operator
     * @param restakingOperator is the address of the restaking operator
     * @param metadataURI is the URI of the operator's metadata
     * @dev Restricted to the DAO
     */
    function callUpdateMetadataURI(IRestakingOperator restakingOperator, string calldata metadataURI) external;

    /**
     * @notice Calls the callDelegateTo function on the target module
     * @param moduleName is the name of the module
     * @param operator is the address of the restaking operator
     * @param approverSignatureAndExpiry the signature of the delegation approver
     * @param approverSalt salt for the signature
     * @dev Restricted to the DAO
     */
    function callDelegateTo(
        bytes32 moduleName,
        address operator,
        ISignatureUtils.SignatureWithExpiry calldata approverSignatureAndExpiry,
        bytes32 approverSalt
    ) external;

    /**
     * @notice Calls the callUndelegate function on the target module
     * @param moduleName is the name of the module
     * @dev Restricted to the DAO
     */
    function callUndelegate(bytes32 moduleName) external returns (bytes32[] memory withdrawalRoot);
}
