// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { IRestakingOperator } from "puffer/interface/IRestakingOperator.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";
import { IERC20 } from "openzeppelin/token/ERC20/IERC20.sol";

/**
 * @title IPufferModuleManager
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferModuleManager {
    /**
     * @notice Thrown if the module name is not allowed
     */
    error ForbiddenModuleName();

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
     * @dev Signature "0xfa1bd67700189b28b5a9085170838266813878ca3237b31a33358644a22a2f0e"
     */
    event WithdrawalsQueued(bytes32 indexed moduleName, uint256 shareAmount, bytes32 withdrawalRoot);

    /**
     * @notice Emitted when the verify and process withdrawals is called
     * @param moduleName is the name of the module
     * @param withdrawalFields are the fields of the withdrawals being proven
     * @param validatorFields are the fields of the validators being proven
     * @dev Signature "0x3f91dfbadd893521ffbbd43362750081af349f220002e6bfb4ffb3c00735f8ac"
     */
    event VerifiedAndProcessedWithdrawals(
        bytes32 indexed moduleName, bytes32[][] validatorFields, bytes32[][] withdrawalFields
    );

    /**
     * @notice Emitted when the Restaking Operator is updated with a new metadata URI
     * @param restakingOperator is the address of the restaking operator
     * @param metadataURI is the new URI of the operator's metadata
     * @dev Signature "0x4cb1b839d29c7a6f051ae51c7b439f2f8f991de54a4b5906503a06a0892ba2c4"
     */
    event RestakingOperatorMetadataURIUpdated(address indexed restakingOperator, string metadataURI);

    /**
     * @notice Emitted when the Puffer Module is delegated
     * @param moduleName the module name to be delegated
     * @param operator the operator to delegate to
     * @dev Signature "0xfa610363b3f4985bba03612919e946ac0bccf11c8e067255de41e530f8cc0997"
     */
    event PufferModuleDelegated(bytes32 indexed moduleName, address operator);

    /**
     * @notice Emitted when the Puffer Module is undelegated
     * @param moduleName the module name to be undelegated
     * @dev Signature "0x4651591b511cac27601595cefbb19b2f0a04ec7b9348230f44a1309b9d70a8c9"
     */
    event PufferModuleUndelegated(bytes32 indexed moduleName);

    /**
     * @notice Emitted when the restaking operator avs signature proof is updated
     * @param restakingOperator is the address of the restaking operator
     * @param digestHash is the message hash
     * @param signer is the address of the signature signer
     * @dev Signature "0x3a6a179c72e503b78f992c3aa1a8d451c366c446c086cee5a811a3d03445a62f"
     */
    event AVSRegistrationSignatureProofUpdated(address indexed restakingOperator, bytes32 digestHash, address signer);

    /**
     * @notice Emitted when a Node Operator verifies withdrawal credentials
     * @param moduleName is the name of the module
     * @param validatorIndices is the indices of the validators
     * @dev Signature "0x6722c9fd02a30e38d993af1ef931e54d0c24d0eae5eba68982773ce120b8ddee"
     */
    event ValidatorCredentialsVerified(bytes32 indexed moduleName, uint40[] validatorIndices);

    /**
     * @notice Emitted when ETH is withdrawn from EigenPod to a PufferModule
     * @param moduleName is the name of the module
     * @param amountToWithdraw is the amount of ETH to withdrawn
     * @dev Signature "0xcc72a3059fae624886e4da6e0b98e575d8cb4f7ea47e3986b5b60182621b7e22"
     */
    event NonBeaconChainETHBalanceWithdrawn(bytes32 indexed moduleName, uint256 amountToWithdraw);

    /**
     * @notice Emitted when the withdrawals are completed
     * @param moduleName is the name of the module
     * @param sharesWithdrawn is the shares withdrawn
     * @dev Signature "0x46ca5934f7ca805e7fbdc05e90e3ecbea495c41e35ba48e24f053c0c3d25af1e"
     */
    event CompletedQueuedWithdrawals(bytes32 indexed moduleName, uint256 sharesWithdrawn);

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
     *
     * @dev See IDelegationManager(EigenLayer) for more details about the other parameters
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
     * @dev See IDelegationManager(EigenLayer) for more details about the other parameters
     * @dev Restricted to the DAO
     */
    function callModifyOperatorDetails(
        IRestakingOperator restakingOperator,
        IDelegationManager.OperatorDetails calldata newOperatorDetails
    ) external;

    /**
     * @notice Calls the verifyAndProcessWithdrawals function from the PufferModule `moduleName` with the given parameters
     * @dev See IEigenPod(EigenLayer) for more details about the other parameters
     */
    function callVerifyAndProcessWithdrawals(
        bytes32 moduleName,
        uint64 oracleTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        BeaconChainProofs.WithdrawalProof[] calldata withdrawalProofs,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields,
        bytes32[][] calldata withdrawalFields
    ) external;

    /**
     * @notice Calls `queueWithdrawals` from the PufferModule `moduleName`
     * @param moduleName is the name of the module
     * @param sharesAmount is the amount of shares to withdraw
     */
    function callQueueWithdrawals(bytes32 moduleName, uint256 sharesAmount) external;

    /**
     * @notice Calls `completeQueuedWithdrawals` from the PufferModule `moduleName`
     * @dev See IDelegationManager(EigenLayer) for more details about the other parameters
     */
    function callCompleteQueuedWithdrawals(
        bytes32 moduleName,
        IDelegationManager.Withdrawal[] calldata withdrawals,
        IERC20[][] calldata tokens,
        uint256[] calldata middlewareTimesIndexes
    ) external;

    /**
     * @notice Calls `verifyWithdrawalCredentials` from the PufferModule `moduleName` with the given parameters
     * @dev See IEigenPod(EigenLayer) for more details about the other parameters
     */
    function callVerifyWithdrawalCredentials(
        bytes32 moduleName,
        uint64 oracleTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        uint40[] calldata validatorIndices,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields
    ) external;

    /**
     * @notice Withdraws ETH from EigenPod to `moduleName`
     * @param amountToWithdraw is the amount of ETH to withdraw
     */
    function callWithdrawNonBeaconChainETHBalanceWei(bytes32 moduleName, uint256 amountToWithdraw) external;

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

    /**
     * @notice Updates AVS registration signature proof
     * @param restakingOperator is the address of the restaking operator
     * @param digestHash is the message hash
     * @param signer is the address of the signature signer
     * @dev Restricted to the DAO
     */
    function updateAVSRegistrationSignatureProof(
        IRestakingOperator restakingOperator,
        bytes32 digestHash,
        address signer
    ) external;
}
