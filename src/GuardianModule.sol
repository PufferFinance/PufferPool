// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { PufferServiceManager } from "puffer/PufferServiceManager.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import { Ownable } from "openzeppelin/access/Ownable.sol";

/**
 * @title Guardian module
 * @author Puffer finance
 * @dev This contract is both {Safe} module, and a logic contract to be called via `delegatecall` from {Safe} (GuardianAccount)
 * @custom:security-contact security@puffer.fi
 */
contract GuardianModule is Ownable, IGuardianModule {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /**
     * @dev Uncompressed ECDSA keys are 65 bytes long
     */
    uint256 internal constant _ECDSA_KEY_LENGTH = 65;

    IEnclaveVerifier public immutable enclaveVerifier;
    Safe public immutable GUARDIANS;

    bytes32 mrsigner;
    bytes32 mrenclave;

    /**
     * @dev Mapping from guardian address => enclave address
     */
    mapping(address => address) internal _guardianEnclaves;

    constructor(IEnclaveVerifier verifier, Safe guardians) Ownable(msg.sender) {
        enclaveVerifier = verifier;
        GUARDIANS = guardians;
    }

    function setGuardianEnclaveMeasurements(bytes32 newMrenclave, bytes32 newMrsigner) public { //@audit don't forget owner modifier
        bytes32 previousMrEnclave = mrenclave;
        bytes32 previousMrsigner = mrsigner;
        mrenclave = newMrenclave;
        mrsigner = newMrsigner;
        emit MrEnclaveChanged(previousMrEnclave, newMrenclave);
        emit MrSignerChanged(previousMrsigner, newMrsigner);
    }

    function validateGuardianSignatures(
        bytes memory pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external view {
        PufferServiceManager serviceManager = PufferServiceManager(msg.sender);

        bytes32 msgToBeSigned = getMessageToBeSigned(serviceManager, pubKey, signature, depositDataRoot);

        Safe guardians = serviceManager.getGuardians();

        address[] memory enclaveAddresses = getGuardiansEnclaveAddresses();
        uint256 validSignatures = 0;

        // Iterate through guardian enclave addresses and make sure that the signers match
        for (uint256 i = 0; i < enclaveAddresses.length;) {
            address currentSigner = ECDSA.recover(msgToBeSigned, guardianEnclaveSignatures[i]);
            if (currentSigner == address(0)) {
                revert Unauthorized();
            }
            if (currentSigner == enclaveAddresses[i]) {
                validSignatures++;
            }
            unchecked {
                ++i;
            }
        }

        if (validSignatures < guardians.getThreshold()) {
            revert Unauthorized();
        }
    }

    function getMessageToBeSigned(
        PufferServiceManager serviceManager,
        bytes memory pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) public view returns (bytes32) {
        return keccak256(abi.encode(pubKey, serviceManager.getWithdrawalPool(), signature, depositDataRoot))
            .toEthSignedMessageHash();
    }

    function rotateGuardianKey(uint256 blockNumber, bytes calldata pubKey, RaveEvidence calldata evidence) external {
        address guardian = msg.sender;

        // Because this is called from the safe via .delegateCall
        // address(this) equals to {Safe}
        // This will revert if the caller is not one of the {Safe} owners
        if (!GUARDIANS.isOwner(msg.sender)) {
            revert Unauthorized();
        }

        if (pubKey.length != _ECDSA_KEY_LENGTH) {
            revert InvalidECDSAPubKey();
        }

        // slither-disable-next-line uninitialized-state-variables
        bool isValid = enclaveVerifier.verifyEvidence({
            blockNumber: blockNumber,
            raveCommitment: keccak256(pubKey),
            mrenclave: mrenclave,
            mrsigner: mrsigner,
            evidence: evidence
        });

        if (!isValid) {
            revert Unauthorized();
        }

        // pubKey[1:] means we need to strip the first byte '0x' if we want to get the correct address
        address computedAddress = address(uint160(uint256(keccak256(pubKey[1:]))));

        _guardianEnclaves[guardian] = computedAddress;

        emit RotatedGuardianKey(guardian, computedAddress, pubKey);
    }

    function isGuardiansEnclaveAddress(address guardian, address enclave) external view returns (bool) {
        // Assert if the stored enclaveAddress equals enclave
        return _guardianEnclaves[guardian] == enclave;
    }

    function getGuardiansEnclaveAddresses() public view returns (address[] memory) {
        address[] memory guardians = GUARDIANS.getOwners();
        address[] memory enclaveAddresses = new address[](guardians.length);

        for (uint256 i = 0; i < guardians.length;) {
            enclaveAddresses[i] = _guardianEnclaves[guardians[i]];
            unchecked {
                ++i;
            }
        }

        return enclaveAddresses;
    }
}
