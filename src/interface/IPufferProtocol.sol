// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Validator } from "puffer/struct/Validator.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { Safe } from "safe-contracts/Safe.sol";

/**
 * @title IPufferProtocol
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferProtocol {
    /**
     * @notice Thrown when the number of BLS public key shares doesn't match guardians number
     * @dev Signature "0x9a5bbd69"
     */
    error InvalidBLSPublicKeyShares();

    /**
     * @notice Thrown when the RAVE evidence is not valid
     * @dev Signature "0x14807c47"
     */
    error InvalidRaveEvidence();

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
     * @notice Thrown when the user is not authorized
     * @dev Signature "0x82b42900"
     */
    error Unauthorized();

    /**
     * @notice Thrown when the BLS public key is not valid
     * @dev Signature "0x7eef7967"
     */
    error InvalidBLSPubKey();

    /**
     * @notice Thrown when validator is not in valid state
     * @dev Signature "0x6d9ba916"
     */
    error InvalidValidatorState();

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
     * @notice Emitted when the new Puffer strategy is created
     * @dev Signature "0x1670437ca2eb58efedc6de6646babe75e13b3ef73af5174bd55db63efeaf41c7"
     */
    event NewPufferStrategyCreated(address strategy);

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
    event ValidatorSkipped(bytes32 indexed strategyName, uint256 skippedValidatorIndex);

    /**
     * @notice Emitted when the Guardians update state of the protocol
     * @param ethAmount is the ETH amount that is not locked in Beacon chain
     * @param lockedETH is the locked ETH amount in Beacon chain
     * @param pufETHTotalSupply is the total supply of the pufETH
     */
    event BackingUpdated(uint256 ethAmount, uint256 lockedETH, uint256 pufETHTotalSupply, uint256 blockNumber);

    /**
     * @notice Emitted when the smoothing commitment amount is changed
     * @dev Signature "0xde1839594da67886999083403f9eae77aa4bc77d812f5d2434899d0f69882885"
     */
    event CommitmentChanged(bytes32 indexed strategyName, uint256 oldSmoothingCommitment, uint256 smoothingCommitment);

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
     * @dev Signature "0x164db4cd8a48da2fe13aa432976a2b2ec884239bb8e411b135d280eb0192a84d"
     */
    event ValidatorKeyRegistered(bytes indexed pubKey, uint256 validatorIndex);

    /**
     * @notice Emitted when the Validator is provisioned
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @dev Signature "0x316b88e106e79895c25a960158d125957aaf3ab3520d6151fbbec5108e19a435"
     */
    event SuccesfullyProvisioned(bytes indexed pubKey, uint256 validatorIndex);

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
     * @notice Emitted when the validator is provisioned
     * @param nodeOperator is the address of the Node Operator
     * @param pubKey is the public key of the Validator
     * @param timestamp is the unix timestamp in seconds
     * @dev Signature "0x38d719b1216fcb012b932840fc8d66e25bb95b58137d2f54de7ffd0edfbdc885"
     */
    event ETHProvisioned(address nodeOperator, bytes indexed pubKey, uint256 timestamp);

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
     * @notice Returns the Strategy Manager
     */
    function EIGEN_STRATEGY_MANAGER() external view returns (IStrategyManager);

    /**
     * @notice Returns the guardian module
     */
    function getGuardianModule() external view returns (GuardianModule);

    /**
     * @notice Returns the protocol fee rate
     */
    function getProtocolFeeRate() external view returns (uint256);

    /**
     * @notice Returns the address of the Withdrawal pool
     */
    function getWithdrawalPool() external view returns (address);

    /**
     * @notice Returns the array of Puffer validators
     * @dev Not to be used on chain
     */
    function getValidators(bytes32 strategyName) external view returns (bytes[] memory);

    /**
     * @notice Returns the array of Node operator's addresses (it uses the same ordering as getValidators())
     * @dev Not to be used on chain
     */
    function getValidatorsAddresses(bytes32 strategyName) external view returns (address[] memory);

    /**
     * @notice Creates a new Puffer strategy with `strategyName`
     * @dev It will revert if you try to create two strategies with the same name
     */
    function createPufferStrategy(bytes32 strategyName) external returns (address);

    /**
     * @notice Returns the smoothing commitment for a `strategyName` (in wei)
     */
    function getSmoothingCommitment(bytes32 strategyName) external view returns (uint256);

    /**
     * @notice Registers a new validator in a `strategyName` queue
     * @dev There is a queue per strategyName and it is FIFO
     */
    function registerValidatorKey(ValidatorKeyData calldata data, bytes32 strategyName) external payable;

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
     * @notice Returns the default straetgy (no restaking)
     */
    function getDefaultStrategy() external view returns (address);

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
