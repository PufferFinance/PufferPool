// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { RaveEvidence } from "puffer/interface/RaveEvidence.sol";

/**
 * @title IEnclaveVerifier interface
 * @author Puffer Finance
 */
interface IEnclaveVerifier {
    struct RSAPubKey {
        bytes modulus;
        bytes exponent;
    }

    /**
     * @notice Thrown if the Evidence that we're trying to verify is stale
     * Evidence should be submitted for the recent block < `FRESHNESS_BLOCKS`
     * @dev Signature "0x5d4ad9a9"
     */
    error StaleEvidence();

    /**
     * @notice Thrown when the user is not authorized
     * @dev Signature "0x82b42900"
     */
    error Unauthorized();

    /**
     * @notice Emitted when the `pubKeyHash` is added to valid pubKeys
     */
    event AddedPubKey(bytes32 pubKeyHash);

    /**
     * @notice Emitted when the `pubKeyHash` is removed from valid pubKeys
     */
    event RemovedPubKey(bytes32 pubKeyHash);

    /**
     * @notice Returns the PufferPool's address
     */
    function POOL() external view returns (address);

    /**
     * @notice Getter for intelRootCAPubKey
     */
    function getIntelRootCAPubKey() external pure returns (RSAPubKey memory);

    /**
     * @notice Verifies the guardian public key
     * @param pubKey is the guardian's public key
     * @param blockNumber is the block number for whcih evidence is created
     * @param evidence is the evidence
     * @param mrenclave is the mrenclave value
     * @param mrsigner is the mrsigner value
     */
    function verifyGuardianPubKey(
        bytes calldata pubKey,
        uint256 blockNumber,
        RaveEvidence calldata evidence,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) external view returns (bool);

    /**
     * @notice Verifies the Validator public key
     * @param pubKey is the Validator's public key
     * @param blockNumber is the block number for whcih evidence is created
     * @param evidence is the evidence
     * @param mrenclave is the mrenclave value
     * @param mrsigner is the mrsigner value
     */
    function verifyValidatorPubKey(
        bytes calldata pubKey,
        uint256 blockNumber,
        // TODO add the remaining fields
        RaveEvidence calldata evidence,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) external view returns (bool);
}
