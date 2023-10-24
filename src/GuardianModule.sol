// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "openzeppelin/utils/cryptography/MessageHashUtils.sol";

/**
 * @title Guardian module
 * @author Puffer finance
 * @dev This contract is responsible for stroing enclave data and validation of guardian signatures
 * @custom:security-contact security@puffer.fi
 */
contract GuardianModule is AccessManaged, IGuardianModule {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /**
     * @dev Uncompressed ECDSA keys are 65 bytes long
     */
    uint256 internal constant _ECDSA_KEY_LENGTH = 65;

    /**
     * @notice Enclave Verifier smart contract
     */
    IEnclaveVerifier public immutable ENCLAVE_VERIFIER;

    /**
     * @notice Guardians {Safe}
     */
    Safe public immutable GUARDIANS;

    /**
     * @dev MRSIGNER value for SGX
     */
    bytes32 internal _mrsigner;
    /**
     * @dev MRENCLAVE value for SGX
     */
    bytes32 internal _mrenclave;

    struct GuardianData {
        bytes enclavePubKey;
        address enclaveAddress;
    }

    mapping(address guardian => GuardianData data) internal _guardianEnclaves;

    constructor(IEnclaveVerifier verifier, Safe guardians, address pufferAuthority) AccessManaged(pufferAuthority) {
        if (address(verifier) == address(0)) {
            revert InvalidAddress();
        }
        if (address(guardians) == address(0)) {
            revert InvalidAddress();
        }
        if (address(verifier) == address(0)) {
            revert InvalidAddress();
        }
        require(address(guardians) != address(0));
        require(address(pufferAuthority) != address(0));
        ENCLAVE_VERIFIER = verifier;
        GUARDIANS = guardians;
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function setGuardianEnclaveMeasurements(bytes32 newMrenclave, bytes32 newMrsigner) external restricted {
        bytes32 previousMrEnclave = _mrenclave;
        bytes32 previousMrsigner = _mrsigner;
        _mrenclave = newMrenclave;
        _mrsigner = newMrsigner;
        emit MrEnclaveChanged(previousMrEnclave, newMrenclave);
        emit MrSignerChanged(previousMrsigner, newMrsigner);
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function validateGuardianSignatures(
        bytes calldata pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes calldata withdrawalCredentials,
        bytes[] calldata guardianEnclaveSignatures
    ) external view {
        Safe guardians = PufferProtocol(msg.sender).GUARDIANS();

        bytes32 msgToBeSigned = getMessageToBeSigned(pubKey, signature, withdrawalCredentials, depositDataRoot);

        address[] memory enclaveAddresses = getGuardiansEnclaveAddresses();
        uint256 validSignatures;

        // Iterate through guardian enclave addresses and make sure that the signers match
        for (uint256 i; i < enclaveAddresses.length;) {
            address currentSigner = ECDSA.recover(msgToBeSigned, guardianEnclaveSignatures[i]);
            if (currentSigner == enclaveAddresses[i]) {
                ++validSignatures;
            }
            unchecked {
                ++i;
            }
        }

        if (validSignatures < guardians.getThreshold()) {
            revert Unauthorized();
        }
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function getMessageToBeSigned(
        bytes memory pubKey,
        bytes calldata signature,
        bytes calldata withdrawalCredentials,
        bytes32 depositDataRoot
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(pubKey, withdrawalCredentials, signature, depositDataRoot)).toEthSignedMessageHash();
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function rotateGuardianKey(uint256 blockNumber, bytes calldata pubKey, RaveEvidence calldata evidence) external {
        address guardian = msg.sender;

        if (!GUARDIANS.isOwner(guardian)) {
            revert Unauthorized();
        }

        if (pubKey.length != _ECDSA_KEY_LENGTH) {
            revert InvalidECDSAPubKey();
        }

        // slither-disable-next-line uninitialized-state-variables
        bool isValid = ENCLAVE_VERIFIER.verifyEvidence({
            blockNumber: blockNumber,
            raveCommitment: keccak256(pubKey),
            mrenclave: _mrenclave,
            mrsigner: _mrsigner,
            evidence: evidence
        });

        if (!isValid) {
            revert InvalidRAVE();
        }

        // pubKey[1:] means we need to strip the first byte '0x' if we want to get the correct address
        address computedAddress = address(uint160(uint256(keccak256(pubKey[1:]))));

        _guardianEnclaves[guardian].enclaveAddress = computedAddress;
        _guardianEnclaves[guardian].enclavePubKey = pubKey;

        emit RotatedGuardianKey(guardian, computedAddress, pubKey);
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function getGuardiansEnclaveAddress(address guardian) external view returns (address) {
        return _guardianEnclaves[guardian].enclaveAddress;
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function getGuardiansEnclaveAddresses() public view returns (address[] memory) {
        address[] memory guardians = GUARDIANS.getOwners();
        address[] memory enclaveAddresses = new address[](guardians.length);

        for (uint256 i; i < guardians.length;) {
            enclaveAddresses[i] = _guardianEnclaves[guardians[i]].enclaveAddress;
            unchecked {
                ++i;
            }
        }

        return enclaveAddresses;
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function getGuardiansEnclavePubkeys() public view returns (bytes[] memory) {
        address[] memory guardians = GUARDIANS.getOwners();
        bytes[] memory enclavePubkeys = new bytes[](guardians.length);

        for (uint256 i; i < guardians.length;) {
            enclavePubkeys[i] = _guardianEnclaves[guardians[i]].enclavePubKey;
            unchecked {
                ++i;
            }
        }

        return enclavePubkeys;
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function getMrenclave() external view returns (bytes32) {
        return _mrenclave;
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function getMrsigner() external view returns (bytes32) {
        return _mrsigner;
    }
}
