// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";

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
     * @notice Emitted when the guardian changes guardian enclave address
     * @param guardian is the address outside of the enclave
     * @param guardianEnclave is the enclave address
     * @param pubKey is the public key
     */
    event RotatedGuardianKey(address guardian, address guardianEnclave, bytes pubKey);

    /**
     * @notice Rotates guardian key
     * @dev If the msg.sender is one of the owners of the `guardianAccount`, the transaction will be executed.
     *      It executes a delegatecall to this smart contract and calls `rotateKeys`
     *      It will update the guardian's enclave key to address derived from the `pubKey`
     */
    function rotateGuardianKey(
        address guardianAccount,
        uint256 blockNumber,
        bytes calldata pubKey,
        RaveEvidence calldata raveEvidence
    ) external;

    /**
     * @notice Returns `true` if the `enclave` is registered to `guardian`
     */
    function isGuardiansEnclaveAddress(address payable guardianAccount, address guardian, address enclave)
        external
        view
        returns (bool);
}
