// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";

/**
 * @title Guardian module
 * @author Puffer Finance
 * @dev This contract is responsible for storing enclave data and validation of guardian signatures
 * @custom:security-contact security@puffer.fi
 */
contract GuardianModule is AccessManaged, IGuardianModule {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;

    /**
     * @dev Uncompressed ECDSA keys are 65 bytes long
     */
    uint256 internal constant _ECDSA_KEY_LENGTH = 65;

    /**
     * @notice Enclave Verifier smart contract
     */
    IEnclaveVerifier public immutable ENCLAVE_VERIFIER;

    /**
     * @dev Guardians set
     */
    EnumerableSet.AddressSet private _guardians;

    /**
     * @dev Threshold for the guardians
     */
    uint256 internal _threshold;

    /**
     * @dev MRSIGNER value for SGX
     */
    bytes32 internal _mrsigner;
    /**
     * @dev MRENCLAVE value for SGX
     */
    bytes32 internal _mrenclave;

    /**
     * @dev Enclave data
     * The guardian doesn't know the Secret Key of an enclave wallet
     */
    struct GuardianData {
        bytes enclavePubKey;
        address enclaveAddress;
    }

    /**
     * @dev Mapping of a Guardian's EOA to enclave data
     */
    mapping(address guardian => GuardianData data) internal _guardianEnclaves;

    constructor(IEnclaveVerifier verifier, address[] memory guardians, uint256 threshold, address pufferAuthority)
        payable
        AccessManaged(pufferAuthority)
    {
        if (address(verifier) == address(0)) {
            revert InvalidAddress();
        }
        if (address(verifier) == address(0)) {
            revert InvalidAddress();
        }
        if (address(pufferAuthority) == address(0)) {
            revert InvalidAddress();
        }
        ENCLAVE_VERIFIER = verifier;
        for (uint256 i = 0; i < guardians.length; ++i) {
            _guardians.add(guardians[i]);
        }
        _threshold = threshold;
    }

    receive() external payable { }

    /*
     * @notice Splits the funds among the guardians
     * @dev This function is called to distribute the balance of the contract equally among the guardians
     *      It calculates the amount per guardian and transfers it to each guardian's address
     *      No need for reentrancy checks because guardians are expected to be EOA's accounts
     */
    function splitGuardianFunds() public {
        address[] memory guardians = _guardians.values();
        uint256 numGuardians = _guardians.length();

        uint256 amountPerGuardian = address(this).balance / numGuardians;

        for (uint256 i = 0; i < guardians.length; ++i) {
            // slither-disable-start reentrancy-unlimited-gas
            // slither-disable-next-line calls-loop
            payable(guardians[i]).transfer(amountPerGuardian);
            // slither-disable-end reentrancy-unlimited-gas
        }
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function validateSkipProvisioning(bytes32 moduleName, uint256 skippedIndex, bytes[] calldata guardianEOASignatures)
        external
        view
    {
        bytes32 signedMessageHash = LibGuardianMessages.getSkipProvisioningMessage(moduleName, skippedIndex);

        // Check the signatures
        bool validSignatures = validateGuardiansEOASignatures({
            eoaSignatures: guardianEOASignatures,
            signedMessageHash: signedMessageHash
        });

        if (!validSignatures) {
            revert Unauthorized();
        }
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function validatePostFullWithdrawalsRoot(
        bytes32 root,
        uint256 blockNumber,
        address[] calldata modules,
        uint256[] calldata amounts,
        bytes[] calldata guardianSignatures
    ) external view {
        // Recreate the message hash
        bytes32 signedMessageHash =
            LibGuardianMessages.getPostFullWithdrawalsRootMessage(root, blockNumber, modules, amounts);

        // Check the signatures
        bool validSignatures =
            validateGuardiansEOASignatures({ eoaSignatures: guardianSignatures, signedMessageHash: signedMessageHash });

        if (!validSignatures) {
            revert Unauthorized();
        }
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function validateProofOfReserve(
        uint256 ethAmount,
        uint256 lockedETH,
        uint256 pufETHTotalSupply,
        uint256 blockNumber,
        uint256 numberOfActiveValidators,
        bytes[] calldata guardianSignatures
    ) external view {
        // Recreate the message hash
        bytes32 signedMessageHash = LibGuardianMessages.getProofOfReserveMessage({
            ethAmount: ethAmount,
            lockedETH: lockedETH,
            pufETHTotalSupply: pufETHTotalSupply,
            blockNumber: blockNumber,
            numberOfActiveValidators: numberOfActiveValidators
        });

        // Check the signatures
        bool validSignatures =
            validateGuardiansEOASignatures({ eoaSignatures: guardianSignatures, signedMessageHash: signedMessageHash });

        if (!validSignatures) {
            revert Unauthorized();
        }
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function validateProvisionNode(
        bytes memory pubKey,
        bytes calldata signature,
        bytes calldata withdrawalCredentials,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external view {
        // Recreate the message hash
        bytes32 signedMessageHash =
            LibGuardianMessages.getMessageToBeSigned(pubKey, signature, withdrawalCredentials, depositDataRoot);

        // Check the signatures
        bool validSignatures = validateGuardiansEnclaveSignatures({
            enclaveSignatures: guardianEnclaveSignatures,
            signedMessageHash: signedMessageHash
        });

        if (!validSignatures) {
            revert Unauthorized();
        }
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function validateGuardiansEOASignatures(bytes[] calldata eoaSignatures, bytes32 signedMessageHash)
        public
        view
        returns (bool)
    {
        return _validateSignatures(_guardians.values(), eoaSignatures, signedMessageHash);
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function validateGuardiansEnclaveSignatures(bytes[] calldata enclaveSignatures, bytes32 signedMessageHash)
        public
        view
        returns (bool)
    {
        return _validateSignatures(getGuardiansEnclaveAddresses(), enclaveSignatures, signedMessageHash);
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
    function addGuardian(address newGuardian) external restricted {
        splitGuardianFunds();
        (bool success) = _guardians.add(newGuardian);
        if (success) {
            emit GuardianAdded(newGuardian);
        }
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function removeGuardian(address guardian) external restricted {
        splitGuardianFunds();
        (bool success) = _guardians.remove(guardian);
        if (success) {
            emit GuardianRemoved(guardian);
        }
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function changeThreshold(uint256 newThreshold) external restricted {
        if (newThreshold > _guardians.length()) {
            revert InvalidThreshold(newThreshold);
        }
        uint256 oldThreshold = _threshold;
        _threshold = newThreshold;
        emit ThresholdChanged(oldThreshold, newThreshold);
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function getThreshold() external view returns (uint256) {
        return _threshold;
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function getGuardians() external view returns (address[] memory) {
        return _guardians.values();
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function rotateGuardianKey(uint256 blockNumber, bytes calldata pubKey, RaveEvidence calldata evidence) external {
        address guardian = msg.sender;

        if (!_guardians.contains(guardian)) {
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
        address[] memory guardians = _guardians.values();
        address[] memory enclaveAddresses = new address[](guardians.length);

        for (uint256 i; i < guardians.length; ++i) {
            enclaveAddresses[i] = _guardianEnclaves[guardians[i]].enclaveAddress;
        }

        return enclaveAddresses;
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function getGuardiansEnclavePubkeys() public view returns (bytes[] memory) {
        address[] memory guardians = _guardians.values();
        bytes[] memory enclavePubkeys = new bytes[](guardians.length);

        for (uint256 i; i < guardians.length; ++i) {
            enclavePubkeys[i] = _guardianEnclaves[guardians[i]].enclavePubKey;
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

    /**
     * @inheritdoc IGuardianModule
     */
    function isGuardian(address account) external view returns (bool) {
        return _guardians.contains(account);
    }

    /**
     * @dev Validates the signatures of the provided signers
     * @param signers The array of signers
     * @param signatures The array of signatures
     * @param signedMessageHash The hash of the signed message
     * @return A boolean indicating whether the signatures are valid
     */
    function _validateSignatures(address[] memory signers, bytes[] calldata signatures, bytes32 signedMessageHash)
        internal
        view
        returns (bool)
    {
        uint256 validSignatures;

        // Iterate through guardian enclave addresses and make sure that the signers match
        for (uint256 i; i < signers.length; ++i) {
            (address currentSigner,,) = ECDSA.tryRecover(signedMessageHash, signatures[i]);
            if (currentSigner == signers[i]) {
                ++validSignatures;
            }
        }

        return validSignatures < _threshold ? false : true;
    }
}
