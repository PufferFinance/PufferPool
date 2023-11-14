// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Validator } from "puffer/struct/Validator.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { IPufferProtocolStorage } from "puffer/interface/IPufferProtocolStorage.sol";
import { Status } from "puffer/struct/Status.sol";
import { Safe } from "safe-contracts/Safe.sol";

/**
 * @title IPufferProtocol
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferProtocol is IPufferProtocolStorage {
    error Failed();
    /**
     * @notice Thrown when the number of BLS public key shares doesn't match guardians number
     * @dev Signature "0x9a5bbd69"
     */
    error InvalidBLSPublicKeySet();

    /**
     * @notice Thrown when the Merkle Proof for a full withdrawal is not valid
     * @dev Signature "0xb05e92fa"
     */
    error InvalidMerkleProof();

    /**
     * @notice Thrown when the strategy name already exists
     * @dev Signature "0xc45546f7"
     */
    error StrategyAlreadyExists();

    /**
     * @notice Thrown when the supplied number of months is not valid
     * @dev Signature "0xa00523fd"
     */
    error InvalidNumberOfMonths();

    /**
     * @notice Thrown when the new validators tires to register, but the limit for this interval is already reached
     * @dev Signature "0xd9873182"
     */
    error ValidatorLimitPerIntervalReached();

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
     */
    error InvalidData();

    /**
     * @notice Thrown if the Creation of new strategy failed
     * @dev Signature "0x04a5b3ee"
     */
    error Create2Failed();

    /**
     * @notice Thrown if the Node operator tries to register with invalid strategy
     * @dev Signature "0x60ac6d15"
     */
    error InvalidPufferStrategy();

    /**
     * @notice Thrown if Guardians try to re-submit the backing data
     * @dev Signature "0xf93417f7"
     */
    error OutsideUpdateWindow();

    /**
     * @notice Emitted when the new Puffer strategy is created
     * @dev Signature "0x1670437ca2eb58efedc6de6646babe75e13b3ef73af5174bd55db63efeaf41c7"
     */
    event NewPufferStrategyCreated(address strategy);

    /**
     * @notice Emitted when the new Puffer `strategyName` is changed to a new strategy
     * @dev Signature "0x38488ea225f6b4bcf21060e716ea744fa5c99fd5de9ea2f8d1b257e1060f9ee1"
     */
    event StrategyChanged(bytes32 indexed strategyName, address oldStrategy, address newStrategy);

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
     * @notice Emitted when the validator interval gets reset
     * @dev Signature "0xf147f5fea5809d6be90362da029bbc2ab19828fbd38e0e426eccc76ae7bba618"
     */
    event IntervalReset();

    /**
     * @notice Emitted when the ETH `amount` in wei is transferred to `to` address
     * @dev Signature "0xba7bb5aa419c34d8776b86cc0e9d41e72d74a893a511f361a11af6c05e920c3d"
     */
    event TransferredETH(address indexed to, uint256 amount);

    /**
     * @notice Emitted when the smoothing commitment is paid
     * @dev Signature "0x6a095c9795d04d9e8a30e23a2f65cb55baaea226bf4927a755762266125afd8c"
     */
    event SmoothingCommitmentPaid(bytes indexed pubKey, uint256 timestamp, uint256 amountPaid);

    /**
     * @notice Emitted when the guardians decide to skip validator provisioning for `strategyName`
     * @dev Signature "0x6a095c9795d04d9e8a30e23a2f65cb55baaea226bf4927a755762266125afd8c"
     */
    event ValidatorSkipped(bytes indexed pubKey, uint256 indexed validatorIndex, bytes32 indexed strategyName);

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
     * @notice Emitted when the strategy weights changes from `olgWeights` to `newWeights`
     * @dev Signature "0x651ca4f91cd6509c3bd83f4eae79f7b55bf243d8b0dc5fc648d6002b06873afe"
     */
    event StrategyWeightsChanged(bytes32[] olgWeights, bytes32[] newWeights);

    /**
     * @notice Emitted when the Validator key is registered
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @param strategyName is the staking Strategy
     * @param usingEnclave is indicating if the validator is using secure enclave
     * @dev Signature "0xc73344cf227e056eee8d82aee54078c9b55323b61d17f61587eb570873f8e319"
     */
    event ValidatorKeyRegistered(
        bytes indexed pubKey, uint256 indexed validatorIndex, bytes32 indexed strategyName, bool usingEnclave
    );

    /**
     * @notice Emitted when the Validator exited and stopped validating
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @param strategyName is the staking Strategy
     * @dev Signature "0xec0dc4352d02ab1358d681da59e62a34af18c126565f98d7c4c71da1315f81f5"
     */
    event ValidatorExited(bytes indexed pubKey, uint256 indexed validatorIndex, bytes32 indexed strategyName);

    /**
     * @notice Emitted when the Validator is provisioned
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @param strategyName is the staking Strategy
     * @dev Signature "0x09290f1d819767ba40f9616823cb23f1e925c228f0d02e5e4818a4fa05d6c487"
     */
    event SuccesfullyProvisioned(bytes indexed pubKey, uint256 indexed validatorIndex, bytes32 indexed strategyName);

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
     * @param strategyName is the staking Strategy
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @return Validator info struct
     */
    function getValidatorInfo(bytes32 strategyName, uint256 validatorIndex) external view returns (Validator memory);

    /**
     * @notice Stops the registration
     * @param strategyName is the staking Strategy
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @dev Can only be called by the Node Operator, and Validator must be in `Pending` state
     */
    function stopRegistration(bytes32 strategyName, uint256 validatorIndex) external;

    /**
     * @notice Stops the validator
     * @dev We will burn pufETH from node operator in case of slashing / receiving less than 32 ETH from a full withdrawal
     * @param strategyName is the staking Strategy
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @param withdrawalAmount is the amount of ETH from the full withdrawal
     * @param wasSlashed is the amount of pufETH that we are burning from the node operator
     * @param merkleProof is the Merkle Proof for a withdrawal
     */
    function stopValidator(
        bytes32 strategyName,
        uint256 validatorIndex,
        uint256 blockNumber,
        uint256 withdrawalAmount,
        bool wasSlashed,
        bytes32[] calldata merkleProof
    ) external;

    /**
     * @notice Skips the next validator for `strategyName`
     * @dev Restricted to Guardians
     */
    function skipProvisioning(bytes32 strategyName, bytes[] calldata guardianEOASignatures) external;

    /**
     * @notice Sets the strategy weights array to `newStrategyWeights`
     * @dev Restricted to DAO
     */
    function setStrategyWeights(bytes32[] calldata newStrategyWeights) external;

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
     * @notice Updates the reserves amounts
     * @dev Restricted to Guardians
     */
    function proofOfReserve(uint256 ethAmount, uint256 lockedETH, uint256 pufETHTotalSupply, uint256 blockNumber)
        external;

    /**
     * @notice Changes the `strategyName` with `newStrategy`
     * @dev Restricted to DAO
     */
    function changeStrategy(bytes32 strategyName, IPufferStrategy newStrategy) external;

    /**
     * @notice Returns the guardian module
     */
    function getGuardianModule() external view returns (IGuardianModule);

    /**
     * @notice Returns the protocol fee rate
     */
    function getProtocolFeeRate() external view returns (uint256);

    /**
     * @notice Returns the address of the Withdrawal pool
     */
    function getWithdrawalPool() external view returns (IWithdrawalPool);

    /**
     * @notice Returns the address of the Withdrawal pool
     */
    function getPufferPool() external view returns (IPufferPool);

    /**
     * @notice Returns the current strategy weights
     */
    function getStrategyWeights() external view returns (bytes32[] memory);

    /**
     * @notice Returns the strategy select index
     */
    function getStrategySelectIndex() external view returns (uint256);

    /**
     * @notice Returns the address for `strategyName`
     */
    function getStrategyAddress(bytes32 strategyName) external view returns (address);

    /**
     * @notice Provisions the next node that is in line for provisioning if the `guardianEnclaveSignatures` are valid
     * @dev You can check who is next for provisioning by calling `getNextValidatorToProvision` method
     */
    function provisionNode(bytes[] calldata guardianEnclaveSignatures) external;

    /**
     * @notice Returns the deposit_data_root
     * @param pubKey is the public key of the validator
     * @param signature is the validator's signature over deposit data
     * @param withdrawalCredentials is the withdrawal credentials (one of Puffer Strategies)
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
    function getValidators(bytes32 strategyName) external view returns (Validator[] memory);

    /**
     * @notice Creates a new Puffer strategy with `strategyName`
     * @dev It will revert if you try to create two strategies with the same name
     */
    function createPufferStrategy(bytes32 strategyName) external returns (address);

    /**
     * @notice Returns the smoothing commitment for a `numberOfMonths` (in wei)
     */
    function getSmoothingCommitment(uint256 numberOfMonths) external view returns (uint256);

    /**
     * @notice Registers a new validator in a `strategyName` queue
     * @dev There is a queue per strategyName and it is FIFO
     */
    function registerValidatorKey(ValidatorKeyData calldata data, bytes32 strategyName, uint256 numberOfMonths)
        external
        payable;

    /**
     * @notice Extends the commitment for a validator in a specific strategy
     * @param strategyName The name of the strategy
     * @param validatorIndex The index of the validator in the strategy
     * @param numberOfMonths The number of months to extend the commitment for
     */
    function extendCommitment(bytes32 strategyName, uint256 validatorIndex, uint256 numberOfMonths) external payable;

    /**
     * @notice Returns the pending validator index for `strategyName`
     */
    function getPendingValidatorIndex(bytes32 strategyName) external view returns (uint256);

    /**
     * @notice Returns the next validator index for provisioning for `strategyName`
     */
    function getNextValidatorToBeProvisionedIndex(bytes32 strategyName) external view returns (uint256);

    /**
     * @notice Returns the next in line for provisioning
     * @dev The order in which the strategies are selected is based on Strategy Weights
     * Every strategy has its own FIFO queue for provisioning
     */
    function getNextValidatorToProvision() external view returns (bytes32 strategyName, uint256 indexToBeProvisioned);

    /**
     * @notice Returns the validator limit per interval
     */
    function getValidatorLimitPerInterval() external view returns (uint256);

    /**
     * @notice Returns the withdrawal credentials for a `strategy`
     */
    function getWithdrawalCredentials(address strategy) external view returns (bytes memory);

    /**
     * @notice Returns the treasury address
     */
    function TREASURY() external view returns (address payable);

    /**
     * @notice Returns the Guardians {Safe} multisig wallet
     */
    function GUARDIANS() external view returns (Safe);
}
