// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { StoppedValidatorInfo } from "puffer/struct/StoppedValidatorInfo.sol";

/**
 * @title IGuardianModule interface
 * @author Puffer Finance
 */
interface IGuardianModule {
    /**
     * @notice Thrown when the ECDSA public key is not valid
     * @dev Signature "0xe3eece5a"
     */
    error InvalidECDSAPubKey();

    /**
     * @notice Thrown when the RAVE evidence is not valid
     * @dev Signature "0x2b3c629b"
     */
    error InvalidRAVE();

    /**
     * @notice Thrown if the address supplied is not valid
     * @dev Signature "0xe6c4247b"
     */
    error InvalidAddress();

    /**
     * @notice Thrown if the threshold value is not valid
     * @dev Signature "0x651a749b"
     */
    error InvalidThreshold(uint256 threshold);

    /**
     * @notice Emitted when the ejection threshold is changed
     * @param oldThreshold is the old threshold value
     * @param newThreshold is the new threshold value
     */
    event EjectionThresholdChanged(uint256 oldThreshold, uint256 newThreshold);

    /**
     * @notice Emitted when the threshold value for guardian signatures is changed
     * @param oldThreshold is the old threshold value
     * @param newThreshold is the new threshold value
     */
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);

    /**
     * @notice Emitted when a guardian is added to the module
     * @param guardian The address of the guardian added
     */
    event GuardianAdded(address guardian);

    /**
     * @notice Emitted when a guardian is removed from the module
     * @param guardian The address of the guardian removed
     */
    event GuardianRemoved(address guardian);

    /**
     * @notice Emitted when the guardian changes guardian enclave address
     * @param guardian is the address outside of the enclave
     * @param guardianEnclave is the enclave address
     * @param pubKey is the public key
     */
    event RotatedGuardianKey(address guardian, address guardianEnclave, bytes pubKey);

    /**
     * @notice Emitted when the mrenclave value is changed
     * @dev SIgnature "0x1ff2c57ef9a384cea0c482d61fec8d708967d266f03266e301c6786f7209904a"
     */
    event MrEnclaveChanged(bytes32 oldMrEnclave, bytes32 newMrEnclave);

    /**
     * @notice Emitted when the mrsigner value is changed
     * @dev Signature "0x1a1fe271c5533136fccd1c6df515ca1f227d95822bfe78b9dd93debf3d709ae6"
     */
    event MrSignerChanged(bytes32 oldMrSigner, bytes32 newMrSigner);

    /**
     * @notice Returns the enclave address registered to `guardian`
     */
    function getGuardiansEnclaveAddress(address guardian) external view returns (address);

    /**
     * @notice Returns the ejection threshold ETH value
     * @dev The ejection threshold is the minimum amount of ETH on the beacon chain required do the validation duties
     * If it drops below this value, the validator will be ejected
     * It is more likely that the validator will run out of Validator Tickets before its balance drops below this value
     * @return The ejection threshold value
     */
    function getEjectionThreshold() external view returns (uint256);

    /**
     * @notice Sets the values for mrEnclave and mrSigner to `newMrenclave` and `newMrsigner`
     */
    function setGuardianEnclaveMeasurements(bytes32 newMrenclave, bytes32 newMrsigner) external;

    /**
     * @notice Validates the update of the number of validators
     */
    function validateTotalNumberOfValidators(
        uint256 newNumberOfValidators,
        uint256 epochNumber,
        bytes[] calldata guardianEOASignatures
    ) external view;

    /**
     * @notice Returns the enclave verifier
     */
    function ENCLAVE_VERIFIER() external view returns (IEnclaveVerifier);

    /**
     * @notice Validates the batch withdrawals calldata
     * @dev The order of the signatures is important
     * The order of the signatures MUST the same as the order of the validators in the validator module
     * @param validatorInfos The information of the stopped validators
     * @param guardianEOASignatures The guardian EOA signatures
     */
    function validateBatchWithdrawals(
        StoppedValidatorInfo[] calldata validatorInfos,
        bytes[] calldata guardianEOASignatures
    ) external;

    /**
     * @notice Validates the node provisioning calldata
     * @dev The order of the signatures is important
     * The order of the signatures MUST the same as the order of the guardians in the guardian module
     * @param validatorIndex is the validator index in Puffer
     * @param pubKey The public key
     * @param signature The signature
     * @param withdrawalCredentials The withdrawal credentials
     * @param depositDataRoot The deposit data root
     * @param guardianEnclaveSignatures The guardian enclave signatures
     */
    function validateProvisionNode(
        uint256 validatorIndex,
        bytes memory pubKey,
        bytes calldata signature,
        bytes calldata withdrawalCredentials,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external view;

    /**
     * @notice Validates the skipping of provisioning for a specific module
     * @param moduleName The name of the module
     * @param skippedIndex The index of the skipped provisioning
     * @param guardianEOASignatures The guardian EOA signatures
     */
    function validateSkipProvisioning(bytes32 moduleName, uint256 skippedIndex, bytes[] calldata guardianEOASignatures)
        external
        view;

    /**
     * @notice Returns the threshold value for guardian signatures
     * @dev The threshold value is the minimum number of guardian signatures required for a transaction to be considered valid
     * @return The threshold value
     */
    function getThreshold() external view returns (uint256);

    /**
     * @notice Returns the list of guardians
     * @dev This function returns an array of addresses representing the guardians
     * @return An array of addresses representing the guardians
     */
    function getGuardians() external view returns (address[] memory);

    /**
     * @notice Adds a new guardian to the module
     * @dev Restricted to the DAO
     * @param newGuardian The address of the new guardian to add
     */
    function addGuardian(address newGuardian) external;

    /**
     * @notice Removes a guardian from the module
     * @dev Restricted to the DAO
     * @param guardian The address of the guardian to remove
     */
    function removeGuardian(address guardian) external;

    /**
     * @notice Changes the threshold value for the guardian signatures
     * @dev Restricted to the DAO
     * @param newThreshold The new threshold value
     */
    function setThreshold(uint256 newThreshold) external;

    /**
     * @notice Changes the ejection threshold value
     * @dev Restricted to the DAO
     * @param newThreshold The new threshold value
     */
    function setEjectionThreshold(uint256 newThreshold) external;

    /**
     * @dev Validates the signatures of the guardians' enclave signatures
     * @param enclaveSignatures The array of enclave signatures
     * @param signedMessageHash The hash of the signed message
     * @return A boolean indicating whether the signatures are valid
     */
    function validateGuardiansEnclaveSignatures(bytes[] calldata enclaveSignatures, bytes32 signedMessageHash)
        external
        view
        returns (bool);

    /**
     * @dev Validates the signatures of the guardians' EOAs.
     * @param eoaSignatures The array of EOAs' signatures.
     * @param signedMessageHash The hash of the signed message.
     * @return A boolean indicating whether the signatures are valid.
     */
    function validateGuardiansEOASignatures(bytes[] calldata eoaSignatures, bytes32 signedMessageHash)
        external
        view
        returns (bool);

    /**
     * @notice Rotates guardian's key
     * @dev If he caller is not a valid guardian or if the RAVE evidence is not valid the tx will revert
     * @param blockNumber is the block number
     * @param pubKey is the public key of the new signature
     * @param evidence is the RAVE evidence
     */
    function rotateGuardianKey(uint256 blockNumber, bytes calldata pubKey, RaveEvidence calldata evidence) external;

    /**
     * @notice Returns the guardians enclave addresses
     */
    function getGuardiansEnclaveAddresses() external view returns (address[] memory);

    /**
     * @notice Returns the guardians enclave public keys
     */
    function getGuardiansEnclavePubkeys() external view returns (bytes[] memory);

    /**
     * @notice Checks if an account is a guardian
     * @param account The address to check
     * @return A boolean indicating whether the account is a guardian
     */
    function isGuardian(address account) external view returns (bool);

    /**
     * @notice Returns the mrenclave value
     */
    function getMrenclave() external view returns (bytes32);

    /**
     * @notice Returns the mrsigner value
     */
    function getMrsigner() external view returns (bytes32);
}
