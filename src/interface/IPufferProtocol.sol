// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Validator } from "puffer/struct/Validator.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IPufferModuleFactory } from "puffer/interface/IPufferModuleFactory.sol";
import { PufferVaultMainnet } from "pufETH/PufferVaultMainnet.sol";
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { Status } from "puffer/struct/Status.sol";
import { Permit } from "puffer/struct/Permit.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";

/**
 * @title IPufferProtocol
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferProtocol {
    /**
     * @notice Thrown when the number of BLS public key shares doesn't match guardians number
     * @dev Signature "0x8cdea6a6"
     */
    error InvalidBLSPublicKeySet();

    /**
     * @notice Thrown when the Merkle Proof for a full withdrawal is not valid
     * @dev Signature "0xb05e92fa"
     */
    error InvalidMerkleProof();

    /**
     * @notice Thrown when the module name already exists
     * @dev Signature "0x2157f2d7"
     */
    error ModuleAlreadyExists();

    /**
     * @notice Thrown when the Node operator tries to withdraw amount bigger than the minimum amount
     * @dev Signature "0x2bcee45d"
     */
    error InvalidValidatorTicketAmount(uint256 amount, uint256 minimumVTAmount);

    /**
     * @notice Thrown when the new validators tires to register to a module, but the limit for this module is already reached
     * @dev Signature "0xb75c5781"
     */
    error ValidatorLimitForModuleReached();

    /**
     * @notice Thrown when the number of BLS private key shares doesn't match guardians number
     * @dev Signature "0x2c8f9aa3"
     */
    error InvalidBLSPrivateKeyShares();

    /**
     * @notice Thrown when the BLS public key is not valid
     * @dev Signature "0x7eef7967"
     */
    error InvalidBLSPubKey();

    /**
     * @notice Thrown when validator is not in valid state
     * @dev Signature "0x3001591c"
     */
    error InvalidValidatorState(Status status);

    /**
     * @notice Thrown if the sender did not send enough ETH in the transaction
     * @dev Signature "0x242b035c"
     */
    error InvalidETHAmount();

    /**
     * @notice Thrown if the oracle tries to submit invalid data
     * @dev Signature "0x5cb045db"
     */
    error InvalidData();

    /**
     * @notice Thrown if the Node operator tries to register with invalid module
     * @dev Signature "0xf2801d96"
     */
    error InvalidPufferModule();

    /**
     * @notice Emitted when the new Puffer module is created
     * @dev Signature "0xd95c47914545148df84d115c3a83350c2b0044a8efa7dbe2cff795a70fe129a1"
     */
    event NewPufferModuleCreated(address module);

    /**
     * @notice Emitted when the new Puffer `moduleName` is changed to a new module
     * @dev Signature "0x7917c855c3fa228f8999ca691902e81578515c4cce59cb85a993a9b2a26f1faa"
     */
    event ModuleChanged(bytes32 indexed moduleName, address oldModule, address newModule);

    /**
     * @notice Emitted when the module's validator limit is changed from `oldLimit` to `newLimit`
     * @dev Signature "0x21e92cbdc47ef718b9c77ea6a6ee50ff4dd6362ee22041ab77a46dacb93f5355"
     */
    event ValidatorLimitPerModuleChanged(uint256 oldLimit, uint256 newLimit);

    /**
     * @notice Emitted when the minimum number of days for ValidatorTickets is changed from `oldMinimumNumberOfDays` to `newMinimumNumberOfDays`
     * @dev Signature "0xc6f97db308054b44394df54aa17699adff6b9996e9cffb4dcbcb127e20b68abc"
     */
    event MinimumVTAmountChanged(uint256 oldMinimumNumberOfDays, uint256 newMinimumNumberOfDays);

    /**
     * @notice Emitted when the ETH `amount` in wei is transferred to `to` address
     * @dev Signature "0xba7bb5aa419c34d8776b86cc0e9d41e72d74a893a511f361a11af6c05e920c3d"
     */
    event TransferredETH(address indexed to, uint256 amount);

    /**
     * @notice Emitted when VT is deposited to the protocol
     * @dev Signature "0xd47eb90c0b945baf5f3ae3f1384a7a524a6f78f1461b354c4a09c4001a5cee9c"
     */
    event ValidatorTicketsDeposited(address indexed node, address indexed depositor, uint256 amount);

    /**
     * @notice Emitted when VT is withdrawn from the protocol
     * @dev Signature "0xdf7e884ecac11650e1285647b057fa733a7bb9f1da100e7a8c22aafe4bdf6f40"
     */
    event ValidatorTicketsWithdrawn(address indexed node, address indexed recipient, uint256 amount);

    /**
     * @notice Emitted when the guardians decide to skip validator provisioning for `moduleName`
     * @dev Signature "0x6a095c9795d04d9e8a30e23a2f65cb55baaea226bf4927a755762266125afd8c"
     */
    event ValidatorSkipped(bytes indexed pubKey, uint256 indexed validatorIndex, bytes32 indexed moduleName);

    /**
     * @notice Emitted when the full withdrawals MerkleRoot `root` for a `blockNumber` is posted
     */
    event FullWithdrawalsRootPosted(uint256 indexed blockNumber, bytes32 root);

    /**
     * @notice Emitted when the module weights changes from `oldWeights` to `newWeights`
     * @dev Signature "0xd4c9924bd67ff5bd900dc6b1e03b839c6ffa35386096b0c2a17c03638fa4ebff"
     */
    event ModuleWeightsChanged(bytes32[] oldWeights, bytes32[] newWeights);

    /**
     * @notice Emitted when the Validator key is registered
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @param moduleName is the staking Module
     * @param usingEnclave is indicating if the validator is using secure enclave
     * @dev Signature "0xc73344cf227e056eee8d82aee54078c9b55323b61d17f61587eb570873f8e319"
     */
    event ValidatorKeyRegistered(
        bytes indexed pubKey, uint256 indexed validatorIndex, bytes32 indexed moduleName, bool usingEnclave
    );

    /**
     * @notice Emitted when the Validator exited and stopped validating
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @param moduleName is the staking Module
     * @dev Signature "0xec0dc4352d02ab1358d681da59e62a34af18c126565f98d7c4c71da1315f81f5"
     */
    event ValidatorExited(bytes indexed pubKey, uint256 indexed validatorIndex, bytes32 indexed moduleName);

    /**
     * @notice Emitted when the Validator is provisioned
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @param moduleName is the staking Module
     * @dev Signature "0x96cbbd073e24b0a7d0cab7dc347c239e52be23c1b44ce240b3b929821fed19a4"
     */
    event SuccessfullyProvisioned(bytes indexed pubKey, uint256 indexed validatorIndex, bytes32 indexed moduleName);

    /**
     * @notice Emitted when the validator is dequeued by the Node operator
     * @param pubKey is the public key of the Validator
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @dev Signature "0x3805d456ec5395c4fa60d9ef7579bee46dad389285d99cfaa00fab5e92e64009"
     */
    event ValidatorDequeued(bytes indexed pubKey, uint256 validatorIndex);

    /**
     * @notice Returns validator information
     * @param moduleName is the staking Module
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @return Validator info struct
     */
    function getValidatorInfo(bytes32 moduleName, uint256 validatorIndex) external view returns (Validator memory);

    /**
     * @notice Deposits Validator Tickets for the `node`
     */
    function depositValidatorTickets(Permit calldata permit, address node) external;

    /**
     * @notice Withdraws the `amount` of Validator Tickers from the `msg.sender` to the `recipient`
     * @dev Each active validator requires node operator to have at least `minimumVtAmount` locked
     */
    function withdrawValidatorTickets(uint128 amount, address recipient) external;

    /**
     * @notice Cancels the Validator registration
     * @param moduleName is the staking Module
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @dev Can only be called by the Node Operator, and Validator must be in `Pending` state
     */
    function cancelRegistration(bytes32 moduleName, uint256 validatorIndex) external;

    /**
     * @notice Submit a valid MerkleProof and get back the Bond deposited if the validator was not slashed
     * @dev We will burn pufETH from node operator in case of slashing / receiving less than 32 ETH from a full withdrawal
     * Anybody can trigger a validator exit as long as the proofs submitted are valid
     * @param moduleName is the staking Module
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @param withdrawalAmount is the amount of ETH from the full withdrawal
     * @param wasSlashed is the amount of pufETH that we are burning from the node operator
     * @param merkleProof is the Merkle Proof for a withdrawal
     */
    function retrieveBond(
        bytes32 moduleName,
        uint256 validatorIndex,
        uint256 blockNumber,
        uint256 withdrawalAmount,
        bool wasSlashed,
        bytes32[] calldata merkleProof
    ) external;

    /**
     * @notice Skips the next validator for `moduleName`
     * @dev Restricted to Guardians
     */
    function skipProvisioning(bytes32 moduleName, bytes[] calldata guardianEOASignatures) external;

    /**
     * @notice Sets the module weights array to `newModuleWeights`
     * @dev Restricted to the DAO
     */
    function setModuleWeights(bytes32[] calldata newModuleWeights) external;

    /**
     * @notice Sets the module limits for `moduleName` to `limit`
     * @dev Restricted to the DAO
     */
    function setValidatorLimitPerModule(bytes32 moduleName, uint128 limit) external;

    /**
     * @notice Changes the `moduleName` with `newModule`
     * @dev Restricted to the DAO
     */
    function changeModule(bytes32 moduleName, IPufferModule newModule) external;

    /**
     * @notice Changes the minimum number amount of VT that must be locked per validator
     * @dev Restricted to the DAO
     */
    function changeMinimumVTAmount(uint256 newMinimumVTAmount) external;

    /**
     * @notice Returns the guardian module
     */
    function GUARDIAN_MODULE() external view returns (IGuardianModule);

    /**
     * @notice Returns the Validator ticket ERC20 token
     */
    function VALIDATOR_TICKET() external view returns (ValidatorTicket);

    /**
     * @notice Returns the Puffer Vault
     */
    function PUFFER_VAULT() external view returns (PufferVaultMainnet);

    /**
     * @notice Returns the Puffer Module Factory
     */
    function PUFFER_MODULE_FACTORY() external view returns (IPufferModuleFactory);

    /**
     * @notice Returns the Puffer Oracle
     */
    function PUFFER_ORACLE() external view returns (IPufferOracle);

    /**
     * @notice Returns the current module weights
     */
    function getModuleWeights() external view returns (bytes32[] memory);

    /**
     * @notice Returns the module select index
     */
    function getModuleSelectIndex() external view returns (uint256);

    /**
     * @notice Returns the address for `moduleName`
     */
    function getModuleAddress(bytes32 moduleName) external view returns (address);

    /**
     * @notice Provisions the next node that is in line for provisioning if the `guardianEnclaveSignatures` are valid
     * @dev You can check who is next for provisioning by calling `getNextValidatorToProvision` method
     */
    function provisionNode(bytes[] calldata guardianEnclaveSignatures) external;

    /**
     * @notice Returns the deposit_data_root
     * @param pubKey is the public key of the validator
     * @param signature is the validator's signature over deposit data
     * @param withdrawalCredentials is the withdrawal credentials (one of Puffer Modules)
     * @return deposit_data_root
     */
    function getDepositDataRoot(bytes calldata pubKey, bytes calldata signature, bytes calldata withdrawalCredentials)
        external
        pure
        returns (bytes32);

    /**
     * @notice Returns the array of Puffer validators
     * @dev OFF-CHAIN function
     */
    function getValidators(bytes32 moduleName) external view returns (Validator[] memory);

    /**
     * @notice Creates a new Puffer module with `moduleName`
     * @param metadataURI is a URI for the operator's metadata, i.e. a link providing more details on the operator.
     * @param delegationApprover is an address to verify signatures when a staker wishes to delegate to the operator, as well as controlling "forced undelegations".
     * @dev Signature verification follows these rules:
     * 1) If this address is left as address(0), then any staker will be free to delegate to the operator, i.e. no signature verification will be performed.
     * 2) If this address is an EOA (i.e. it has no code), then we follow standard ECDSA signature verification for delegations to the operator.
     * 3) If this address is a contract (i.e. it has code) then we forward a call to the contract and verify that it returns the correct EIP-1271 "magic value".
     * @dev It will revert if you try to create two modules with the same name
     */
    function createPufferModule(bytes32 moduleName, string calldata metadataURI, address delegationApprover)
        external
        returns (address);

    /**
     * @notice Registers a new validator key in a `moduleName` queue with a permit
     * @dev There is a queue per moduleName and it is FIFO
     *
     * If you are depositing without the permit, make sure to .approve pufETH to PufferProtocol
     * and populate permit.amount with the correct amount
     *
     * @param data The validator key data
     * @param moduleName The name of the module
     * @param numberOfDays The number of days for the registration
     * @param pufETHPermit The permit for the pufETH
     * @param vtPermit The permit for the ValidatorTicket
     */
    function registerValidatorKey(
        ValidatorKeyData calldata data,
        bytes32 moduleName,
        uint256 numberOfDays,
        Permit calldata pufETHPermit,
        Permit calldata vtPermit
    ) external payable;

    /**
     * @notice Returns the pending validator index for `moduleName`
     */
    function getPendingValidatorIndex(bytes32 moduleName) external view returns (uint256);

    /**
     * @notice Returns the next validator index for provisioning for `moduleName`
     */
    function getNextValidatorToBeProvisionedIndex(bytes32 moduleName) external view returns (uint256);

    /**
     * @notice Returns the amount of Validator Tickets in the PufferProtocol for the `owner`
     */
    function geValidatorTicketsBalance(address owner) external returns (uint256);

    /**
     * @notice Returns the next in line for provisioning
     * @dev The order in which the modules are selected is based on Module Weights
     * Every module has its own FIFO queue for provisioning
     */
    function getNextValidatorToProvision() external view returns (bytes32 moduleName, uint256 indexToBeProvisioned);

    /**
     * @notice Returns the withdrawal credentials for a `module`
     */
    function getWithdrawalCredentials(address module) external view returns (bytes memory);

    /**
     * @notice Returns the minimum amount of Validator Tokens to run a validator
     */
    function getMinimumVtAmount() external view returns (uint256);
}
