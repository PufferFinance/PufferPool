// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import {RaveEvidence} from "puffer/interface/RaveEvidence.sol";

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
     * @notice Verifies remote attestation evidence: the report contains the expected MRENCLAVE/MRSIGNER values, a valid TCB status, and was signed by an Intel-issued x509 certificate. The report will contain a 64B payload in the form (32B_Commitment || 32B_BlockHash), where 32B_Blockhash is a recent L1 blockhash and 32B_Commitment is a keccak256 hash that the enclave is committing to. The calling contract is expected to precompute raveCommitment from public inputs. The function returns true if the report is valid and the extracted payload matches the expected.
     * @param blockNumber is the block number to fetch 32B_Blockhash
     * @param raveCommitment is the keccak256 hash commitment 32B_Commitment
     * @param evidence is the remote attestation evidence
     * @param mrenclave is the MRENCLAVE value expected by the calling contract
     * @param mrsigner is the MRSIGNER value expected by the calling contract
     */
    function verifyEvidence(
        uint256 blockNumber,
        bytes32 raveCommitment,
        RaveEvidence calldata evidence,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) external view returns (bool);
}
