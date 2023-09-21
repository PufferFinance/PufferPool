// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Validator } from "puffer/struct/Validator.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { IEnclaveVerifier } from "puffer/interface/IEnclaveVerifier.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";

/**
 * @title IPufferServiceManager
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferServiceManager {
    /**
     * @notice Thrown if the EnclaveVerifier could not verify Rave evidence of custody
     * @dev Signature "0x14236792"
     */
    error CouldNotVerifyCustody();

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
     * @notice Emitted when validator is not in valid status
     * @dev Signature "0xd16d73a340074473a3bf3144bb6bd4304a0bd8691e555d51bf07356c2521c50d"
     */
    event InvalidValidatorStatus(bytes pubKey);

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
     * @notice Emitted when the treasury address changes from `oldTreasury` to `newTreasury`
     * @dev Signature "0x8c3aa5f43a388513435861bf27dfad7829cd248696fed367c62d441f62954496"
     */
    event TreasuryChanged(address oldTreasury, address newTreasury);

    /**
     * @notice Emitted when the Guaridan enclave measurements are changed
     * @dev signature "0x9a538ef1307d6ba0812109ae1345331f1a76ba6a7ed805a0b450c7d198c389ce"
     */
    event GuardianNodeEnclaveMeasurementsChanged(
        bytes32 oldMrenclave, bytes32 mrenclave, bytes32 oldMrsigner, bytes32 mrsigner
    );

    /**
     * @notice Emitted when the protocol fee changes from `oldValue` to `newValue`
     * @dev Signature "0xff4822c8e0d70b6faad0b6d31ab91a6a9a16096f3e70328edbb21b483815b7e6"
     */
    event ProtocolFeeRateChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the guardians address changes from `oldGuardians` to `newGuardians`
     * @dev Signature "0x6ec152e1a709322ea96ec4d6e8c6acc29aeba80455657f617b6ac837b100654a"
     */
    event GuardiansChanged(address oldGuardians, address newGuardians);

    /**
     * @param enclaveVerifier is the address of Enclave verifier contract
     * @dev Signature "0x60e300c919f110ebd183109296d6cd03856a84f64cb7acb91abde69baefd0d7e"
     */
    event EnclaveVerifierChanged(address enclaveVerifier);

    /**
     * @notice Emitted when the Validator key is registered
     * @param pubKey is the validator public key
     * @dev Signature "0x4627afae6730ccc8148672cbdd43af9f21bc62e234cd6267fd80a0d7395e53b0"
     */
    event ValidatorKeyRegistered(bytes pubKey);

    event SuccesfullyProvisioned(bytes pubKey);

    event FailedToProvision(bytes pubKey);

    /**
     * @notice Emitted when the enclave measurements are changed
     * @dev signature "0xe7bb9721183c30b64a866f4684c4b1a3fed5728dc61aec1cfa5de2237e64f1db"
     */
    event NodeEnclaveMeasurementsChanged(
        bytes32 oldMrenclave, bytes32 mrenclave, bytes32 oldMrsigner, bytes32 mrsigner
    );

    /**
     * @notice Emitted when the validator is dequeued by the Node operator
     * @param pubKey is the public key of the Validator
     * @dev Signature "0xcb54ff5ec05355289c7faf3481c52a526f0e00e75484584dc9cbb72e5a7ed4cf"
     */
    event ValidatorDequeued(bytes pubKey);

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
     * @notice Returns the `mrenclave` and `mrsigner` values
     */
    function getNodeEnclaveMeasurements() external returns (bytes32 mrenclave, bytes32 mrsigner);

    /**
     * @notice Returns the `mrenclave` and `mrsigner` values
     */
    function getGuardianEnclaveMeasurements() external returns (bytes32 mrenclave, bytes32 mrsigner);

    /**
     * @notice Returns the Enclave verifier
     */
    function getEnclaveVerifier() external view returns (IEnclaveVerifier);

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
