// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";

/**
 * @title IGuardianModule interface
 * @author Puffer Finance
 */
interface IGuardianModule {
    /**
     * @notice Thrown when the user is not authorized
     * @dev Signature "0x82b42900"
     */
    error Unauthorized();

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
     * @notice Returns `true` if the `enclave` is registered to `guardian`
     */
    function isGuardiansEnclaveAddress(address guardian, address enclave) external view returns (bool);

    /**
     * @notice Sets the values for mrEnclave and mrSigner to `newMrenclave` and `newMrsigner`
     */
    function setGuardianEnclaveMeasurements(bytes32 newMrenclave, bytes32 newMrsigner) external;

    function ENCLAVE_VERIFIER() external view returns (IEnclaveVerifier);

    /**
     * @notice Validates that the guardians enclaves signed on the data.
     * @dev If the signatures are invalid / guardians threshold is not reached the tx will revert
     * @param pubKey is the node operator's public key
     * @param signature is the BLS signature of the deposit data
     * @param depositDataRoot is the hash of the deposit data
     * @param withdrawalCredentials are the withdrawal credentials for this validator
     * @param guardianEnclaveSignatures array of enclave signatures that we are validating
     */
    function validateGuardianSignatures(
        bytes memory pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes calldata withdrawalCredentials,
        bytes[] calldata guardianEnclaveSignatures
    ) external view;

    /**
     * @notice Returns the message that the guardian's enclave needs to sign
     * @param signature is the BLS signature of the deposit data
     * @param withdrawalCredentials are the withdrawal credentials for this validator
     * @param depositDataRoot is the hash of the deposit data
     * @return hash of the data
     */
    function getMessageToBeSigned(
        bytes memory pubKey,
        bytes calldata signature,
        bytes calldata withdrawalCredentials,
        bytes32 depositDataRoot
    ) external pure returns (bytes32);

    /**
     * @notice Rotates guardian's key
     * @dev If he caller is not a valid guardian or if the RAVE evidence is not valid the tx will revert
     * @param blockNumber is the block number
     * @param pubKey is the public key of the new signature
     * @param evidence is the RAVE evidence
     */
    function rotateGuardianKey(uint256 blockNumber, bytes calldata pubKey, RaveEvidence calldata evidence) external;

    /**
     * @notice Returns the guarardians enclave addresses
     */
    function getGuardiansEnclaveAddresses() external view returns (address[] memory);

    /**
     * @notice Returns the guarardians enclave public keys
     */
    function getGuardiansEnclavePubkeys() external view returns (bytes[] memory);

    /**
     * @notice Returns the mrenclave value
     */
    function getMrenclave() external view returns (bytes32);

    /**
     * @notice Returns the mrsigner value
     */
    function getMrsigner() external view returns (bytes32);
}
