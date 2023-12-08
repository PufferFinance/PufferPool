// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Validator } from "puffer/struct/Validator.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { IPufferModuleFactory } from "puffer/interface/IPufferModuleFactory.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { IPufferProtocolStorage } from "puffer/interface/IPufferProtocolStorage.sol";
import { Status } from "puffer/struct/Status.sol";
import { Permit } from "puffer/struct/Permit.sol";

/**
 * @title IPufferProtocol
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferProtocol is IPufferProtocolStorage {
    /**
     * @notice Thrown when external call failed
     * @dev Signature "0x625a40e6"
     */
    error Failed();

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
     * @notice Thrown when the new validators tires to register, but the limit for this interval is already reached
     * @dev Signature "0xa00523fd"
     */
    error ValidatorLimitPerIntervalReached();

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
     * @notice Thrown if Guardians try to re-submit the backing data
     * @dev Signature "0xf93417f7"
     */
    error OutsideUpdateWindow();

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
     * @notice Emitted when the Guardians fee rate is changed from `oldRate` to `newRate`
     * @dev Signature "0xdc450026d966b67c62d26cf532d9a568be6c73c01251576c5d6a71bb19463d2f"
     */
    event GuardiansFeeRateChanged(uint256 oldRate, uint256 newRate);

    /**
     * @notice Emitted when the Withdrawal Pool rate is changed from `oldRate` to `newRate`
     * @dev Signature "0x7b574a9dff23e9e2774a4ee52a42ad285a36eb8dd120eeebc5568d3b02f0683c"
     */
    event WithdrawalPoolRateChanged(uint256 oldRate, uint256 newRate);

    /**
     * @notice Emitted when the module's validator limit is changed from `oldLimit` to `newLimit`
     * @dev Signature "0x21e92cbdc47ef718b9c77ea6a6ee50ff4dd6362ee22041ab77a46dacb93f5355"
     */
    event ValidatorLimitPerModuleChanged(uint256 oldLimit, uint256 newLimit);

    /**
     * @notice Emitted when the ETH `amount` in wei is transferred to `to` address
     * @dev Signature "0xba7bb5aa419c34d8776b86cc0e9d41e72d74a893a511f361a11af6c05e920c3d"
     */
    event TransferredETH(address indexed to, uint256 amount);

    /**
     * @notice Emitted when the smoothing commitment is paid
     * @dev Signature "0x84e6610d0de4b996419eca9cf06b11fc13c256051f73673c802822674928fb9a"
     */
    event SmoothingCommitmentPaid(bytes indexed pubKey, uint256 amountPaid);

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
     * @notice Emitted when the Guardians update state of the protocol
     * @param ethAmount is the ETH amount that is not locked in Beacon chain
     * @param lockedETH is the locked ETH amount in Beacon chain
     * @param pufETHTotalSupply is the total supply of the pufETH
     */
    event BackingUpdated(uint256 ethAmount, uint256 lockedETH, uint256 pufETHTotalSupply, uint256 blockNumber);

    /**
     * @notice Emitted when the smoothing commitments are changed
     * @dev Signature "0xa1c728453af1b7abc9e0f6046d262db82ac81ccb163125d0cf365bae5dc94475"
     */
    event CommitmentsChanged(uint256[] oldCommitments, uint256[] newCommitments);

    /**
     * @notice Emitted when the protocol fee changes from `oldValue` to `newValue`
     * @dev Signature "0xff4822c8e0d70b6faad0b6d31ab91a6a9a16096f3e70328edbb21b483815b7e6"
     */
    event ProtocolFeeRateChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the validator limit per interval is changed from `oldLimit` to `newLimit`
     * @dev Signature "0xd6c37e61a7f770549c535431a7a63b047395ebed26acefc1cab277cbbeb1d8b7"
     */
    event ValidatorLimitPerIntervalChanged(uint256 oldLimit, uint256 newLimit);

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
     * @dev Signature "0x09290f1d819767ba40f9616823cb23f1e925c228f0d02e5e4818a4fa05d6c487"
     */
    event SuccesfullyProvisioned(bytes indexed pubKey, uint256 indexed validatorIndex, bytes32 indexed moduleName);

    /**
     * @notice Emitted when the Validator key is failed to be provisioned
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @dev Signature "0x8570512b93af33936e8fa6bfcd755f2c72c42c90569dc288b2e38e839943f0cd"
     */
    event FailedToProvision(bytes indexed pubKey, uint256 validatorIndex);

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
     * @notice Stops the registration
     * @param moduleName is the staking Module
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @dev Can only be called by the Node Operator, and Validator must be in `Pending` state
     */
    function stopRegistration(bytes32 moduleName, uint256 validatorIndex) external;

    /**
     * @notice Stops the validator
     * @dev We will burn pufETH from node operator in case of slashing / receiving less than 32 ETH from a full withdrawal
     * @param moduleName is the staking Module
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @param withdrawalAmount is the amount of ETH from the full withdrawal
     * @param wasSlashed is the amount of pufETH that we are burning from the node operator
     * @param merkleProof is the Merkle Proof for a withdrawal
     */
    function stopValidator(
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
     * @dev Restricted to DAO
     */
    function setModuleWeights(bytes32[] calldata newModuleWeights) external;

    /**
     * @notice Sets the module limits for `moduleName` to `limit`
     * @dev Restricted to DAO
     */
    function setValidatorLimitPerModule(bytes32 moduleName, uint128 limit) external;

    /**
     * @notice Sets the protocol fee rate
     * @dev 1% equals `1 * FixedPointMathLib.WAD`
     *
     * Restricted to DAO
     */
    function setProtocolFeeRate(uint256 protocolFeeRate) external;

    /**
     * @notice Sets the withdrawal pool rate
     * @dev 1% equals `1 * FixedPointMathLib.WAD`
     *
     * Restricted to DAO
     */
    function setWithdrawalPoolRate(uint256 newRate) external;

    /**
     * @notice Sets guardians fee rate
     * @dev 1% equals `1 * FixedPointMathLib.WAD`
     *
     * Restricted to DAO
     */
    function setGuardiansFeeRate(uint256 newRate) external;

    /**
     * @notice Sets the validator limit per interval to `newLimit`
     * @dev Restricted to DAO
     */
    function setValidatorLimitPerInterval(uint256 newLimit) external;

    /**
     * @notice Sets the smmothing commitment amounts
     * @dev Restricted to DAO
     */
    function setSmoothingCommitments(uint256[] calldata smoothingCommitments) external;

    /**
     * @notice Updates the proof of reserve by checking the signatures of the guardians
     * @param ethAmount The amount of ETH
     * @param lockedETH The locked ETH amount on Beacon Chain
     * @param pufETHTotalSupply The total supply of pufETH tokens
     * @param blockNumber The block number
     * @param numberOfActiveValidators The number of all active validators on Beacon Chain
     * @param guardianSignatures The guardian signatures
     */
    function proofOfReserve(
        uint256 ethAmount,
        uint256 lockedETH,
        uint256 pufETHTotalSupply,
        uint256 blockNumber,
        uint256 numberOfActiveValidators,
        bytes[] calldata guardianSignatures
    ) external;

    /**
     * @notice Changes the `moduleName` with `newModule`
     * @dev Restricted to DAO
     */
    function changeModule(bytes32 moduleName, IPufferModule newModule) external;

    /**
     * @notice Returns the guardian module
     */
    function GUARDIAN_MODULE() external view returns (IGuardianModule);

    /**
     * @notice Returns the Puffer Pool
     */
    function POOL() external view returns (IPufferPool);

    /**
     * @notice Returns the Withdrawal Pool
     */
    function WITHDRAWAL_POOL() external view returns (IWithdrawalPool);

    /**
     * @notice Returns the Puffer Module Factory
     */
    function PUFFER_MODULE_FACTORY() external view returns (IPufferModuleFactory);

    /**
     * @notice Returns the protocol fee rate
     */
    function getProtocolFeeRate() external view returns (uint256);

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
     * @dev It will revert if you try to create two modules with the same name
     */
    function createPufferModule(bytes32 moduleName) external returns (address);

    /**
     * @notice Returns the smoothing commitment for a `numberOfMonths` (in wei)
     */
    function getSmoothingCommitment(uint256 numberOfMonths) external view returns (uint256);

    /**
     * @notice Registers a new validator key in a `moduleName` queue with a permit
     * @dev There is a queue per moduleName and it is FIFO
     *
     * If you are depositing without the permit, make sure to .approve pufETH to PufferProtocol
     * and populate permit.amount with the correct amount
     *
     * @param data The validator key data
     * @param moduleName The name of the module
     * @param numberOfMonths The number of months for the registration
     * @param permit The permit for the registration
     */
    function registerValidatorKeyPermit(
        ValidatorKeyData calldata data,
        bytes32 moduleName,
        uint256 numberOfMonths,
        Permit calldata permit
    ) external payable;

    /**
     * @notice Registers a new validator in a `moduleName` queue
     * @dev There is a queue per moduleName and it is FIFO
     */
    function registerValidatorKey(ValidatorKeyData calldata data, bytes32 moduleName, uint256 numberOfMonths)
        external
        payable;

    /**
     * @notice Extends the commitment for a validator in a specific module
     * @param moduleName The name of the module
     * @param validatorIndex The index of the validator in the module
     * @param numberOfMonths The number of months to extend the commitment for
     */
    function extendCommitment(bytes32 moduleName, uint256 validatorIndex, uint256 numberOfMonths) external payable;

    /**
     * @notice Returns the pending validator index for `moduleName`
     */
    function getPendingValidatorIndex(bytes32 moduleName) external view returns (uint256);

    /**
     * @notice Returns the next validator index for provisioning for `moduleName`
     */
    function getNextValidatorToBeProvisionedIndex(bytes32 moduleName) external view returns (uint256);

    /**
     * @notice Returns the next in line for provisioning
     * @dev The order in which the modules are selected is based on Module Weights
     * Every module has its own FIFO queue for provisioning
     */
    function getNextValidatorToProvision() external view returns (bytes32 moduleName, uint256 indexToBeProvisioned);

    /**
     * @notice Returns the validator limit per interval
     */
    function getValidatorLimitPerInterval() external view returns (uint256);

    /**
     * @notice Returns the withdrawal credentials for a `module`
     */
    function getWithdrawalCredentials(address module) external view returns (bytes memory);

    /**
     * @notice Returns the treasury address
     */
    function TREASURY() external view returns (address payable);
}
