// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Validator } from "puffer/struct/Validator.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";

/**
 * @title IPufferServiceManager
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferServiceManager {
    /**
     * @notice Thrown when the number of BLS public key shares doesn't match guardians number
     * @dev Signature "0x9a5bbd69"
     */
    error InvalidBLSPublicKeyShares();

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
     * @notice Emitted when the Execution rewards split rate in changed from `oldValue` to `newValue`
     * @dev Signature "0x27449eb3aaae64a55d5d46a9adbcc8e1e38857748959a38693d78c36b74eacff"
     */
    event ExecutionCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the Consensus rewards split rate in changed from `oldValue` to `newValue`
     * @dev Signature "0x9066ee0e03e4694bb525f39a319a26ed219db1f8045f1aa5d3d8ee5d826f8b0e"
     */
    event ConsensusCommissionChanged(uint256 oldValue, uint256 newValue);
    
    /**
     * @notice Emitted when the Execution rewards commitment amounts is changed changed from `oldValue` to `newValue`
     * @dev Signature "0x7cf6042ae9b3bb2eecdbbb1050f16c75f96746fd9d18fe2a8e2171ab7086cf6a"
     */
    event ExecutionRewardsCommitmentChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the protocol fee changes from `oldValue` to `newValue`
     * @dev Signature "0xff4822c8e0d70b6faad0b6d31ab91a6a9a16096f3e70328edbb21b483815b7e6"
     */
    event ProtocolFeeRateChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the Validator key is registered
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @dev Signature "0x164db4cd8a48da2fe13aa432976a2b2ec884239bb8e411b135d280eb0192a84d"
     */
    event ValidatorKeyRegistered(bytes pubKey, uint256 validatorIndex);

    /**
     * @notice Emitted when the Validator is provisioned
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @dev Signature "0x316b88e106e79895c25a960158d125957aaf3ab3520d6151fbbec5108e19a435"
     */
    event SuccesfullyProvisioned(bytes pubKey, uint256 validatorIndex);

    /**
     * @notice Emitted when the Validator key is failed to be provisioned
     * @param pubKey is the validator public key
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @dev Signature "0x8570512b93af33936e8fa6bfcd755f2c72c42c90569dc288b2e38e839943f0cd"
     */
    event FailedToProvision(bytes pubKey, uint256 validatorIndex);

    /**
     * @notice Emitted when the validator is dequeued by the Node operator
     * @param pubKey is the public key of the Validator
     * @param validatorIndex is the internal validator index in Puffer Finance, not to be mistaken with validator index on Beacon Chain
     * @dev Signature "0x3805d456ec5395c4fa60d9ef7579bee46dad389285d99cfaa00fab5e92e64009"
     */
    event ValidatorDequeued(bytes pubKey, uint256 validatorIndex);

    /**
     * @notice Emitted when the validator is provisioned
     * @param nodeOperator is the address of the Node Operator
     * @param blsPubKey is the public key of the Validator
     * @param timestamp is the unix timestamp in seconds
     * @dev Signature "0x38d719b1216fcb012b932840fc8d66e25bb95b58137d2f54de7ffd0edfbdc885"
     */
    event ETHProvisioned(address nodeOperator, bytes blsPubKey, uint256 timestamp);

    /**
     * @notice Returns validator information
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @return Validator info struct
     */
    function getValidatorInfo(uint256 validatorIndex) external view returns (Validator memory);

    /**
     * @notice Stops the registration
     * @param validatorIndex is the Index of the validator in Puffer, not to be mistaken with Validator index on beacon chain
     * @dev Can only be called by the Node Operator, and Validator must be in `Pending` state
     */
    function stopRegistration(uint256 validatorIndex) external;

    /**
     * @notice Returns the Strategy Manager
     */
    function EIGEN_STRATEGY_MANAGER() external view returns (IStrategyManager);

    /**
     * @notice Sets the execution rewards split to `newValue`
     */
    function setExecutionCommission(uint256 newValue) external;

    /**
     * @notice Sets the consensus rewards split to `newValue`
     */
    function setConsensusCommission(uint256 newValue) external;

    /**
     * @notice Returns Consensus Commission
     */
    function getConsensusCommission() external view returns (uint256);

    /**
     * @notice Returns Execution Commission
     */
    function getExecutionCommission() external view returns (uint256);

    function getGuardianModule() external view returns (GuardianModule);

    function getProtocolFeeRate() external view returns (uint256);

    /**
     * @notice Returns the address of the Withdrawal pool
     */
    function getWithdrawalPool() external view returns (address);

    /**
     * @notice Returns the address of the Consensus vault
     */
    function getConsensusVault() external view returns (address);

    /**
     * @notice Returns the address of the Execution rewards vault
     */
    function getExecutionRewardsVault() external view returns (address);

    /**
     * @notice Returns the treasury address
     */
    function TREASURY() external view returns (address payable);
}
