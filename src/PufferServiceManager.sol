// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { ValidatorRaveData } from "puffer/struct/ValidatorRaveData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Status } from "puffer/struct/Status.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";

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
     * @notice Thrown when validator is not in valid status for withdrawing bond
     * @dev Signature "0xa36c527f"
     */
    error InvalidValidatorStatus();

    /**
     * @notice Emitted when the Validator key is registered
     * @param pubKey is the validator public key
     * @dev Signature "0x4627afae6730ccc8148672cbdd43af9f21bc62e234cd6267fd80a0d7395e53b0"
     */
    event ValidatorKeyRegistered(bytes pubKey);

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
}

/**
 * @title PufferServiceManager
 * @author Puffer Finance
 * @notice PufferServiceManager TODO:
 * @custom:security-contact security@puffer.fi
 */
contract PufferServiceManager is IPufferServiceManager {
    using ECDSA for bytes32;

    /**
     * @dev BLS public keys are 48 bytes long
     */
    uint256 internal constant _BLS_PUB_KEY_LENGTH = 48;

    /**
     * @notice Puffer Pool
     */
    PufferPool public immutable POOL;

    IEnclaveVerifier internal _enclaveVerifier;

    // State variables

    bytes32 internal _mrenclave;
    bytes32 internal _mrsigner;

    /**
     * @dev Next validator index for provisioning queue
     */
    uint256 pendingValidatorIndex;

    /**
     * @dev Index of the validator that will be provisioned next
     */
    uint256 validatorIndexToBeProvisionedNext;

    mapping(uint256 => Validator) internal _validators;

    constructor(PufferPool pool) {
        POOL = pool;
    }

    function registerValidatorKey(ValidatorKeyData calldata data) external {
        // Sanity check on blsPubKey
        if (data.blsPubKey.length != _BLS_PUB_KEY_LENGTH) {
            revert InvalidBLSPubKey();
        }

        // To prevent spamming the queue
        // PufferAVS.isEligibleForRegisteringValidatorKey(msg.sender, data);

        // PufferAVS logiv

        // 1. make sure that the node operator is opted to our AVS
        // 2. make sure that he has enough WETH delegated

        Validator memory validator;
        validator.pubKey = data.blsPubKey;
        validator.node = msg.sender;

        _validators[pendingValidatorIndex] = validator;

        ++pendingValidatorIndex;

        // Determine bond requirement from inputs
        // uint256 validatorBondRequirement =
        //     _getValidatorBondRequirement(data.evidence.report.length, data.blsEncryptedPrivKeyShares.length);
        // if (msg.value != validatorBondRequirement) {
        //     revert InvalidAmount();
        // }

        // // Verify enclave remote attestation evidence
        // if (validatorBondRequirement != _nonCustodialBondRequirement) {
        //     bytes32 raveCommitment = _buildNodeRaveCommitment(data, POOL.getWithdrawalPool());
        //     _verifyKeyRequirements(data, raveCommitment);
        // }

        emit ValidatorKeyRegistered(data.blsPubKey);
    }

    function provisionNodeETH(
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external {
        uint256 index = validatorIndexToBeProvisionedNext;

        ++validatorIndexToBeProvisionedNext;

        Validator memory validator = _validators[index];

        if (validator.status != Status.PENDING) {
            revert InvalidValidatorStatus();
        }

        // TODO: we need to check that the node operator has enough WETH delegated and that it is opted to our AVS

        // Validate guardian signatures
        _validateGuardianSignatures({
            pubKey: validator.pubKey,
            guardianEnclaveSignatures: guardianEnclaveSignatures,
            signature: signature,
            depositDataRoot: depositDataRoot
        });

        _validators[index].status = Status.VALIDATING;

        emit ETHProvisioned(validator.node, validator.pubKey, block.timestamp);

        POOL.createValidator({
            pubKey: validator.pubKey,
            withdrawalCredentials: _getWithdrawalCredentials(),
            signature: signature,
            depositDataRoot: depositDataRoot
        });
    }

    function getValidators() external view returns (bytes[] memory) {
        uint256 numOfValidators = validatorIndexToBeProvisionedNext + 1;

        bytes[] memory validators = new bytes[](numOfValidators);

        for (uint256 i = numOfValidators; i > 0; i--) {
            validators[i] = bytes(_validators[i].pubKey);
        }

        return validators;
    }

    function stopRegistration(uint256 validatorIndex) external {
        // `msg.sender` is the Node Operator
        Validator storage validator = _validators[validatorIndex];

        if (validator.status != Status.PENDING) {
            revert InvalidValidatorStatus();
        }

        if (msg.sender != validator.node) {
            revert Unauthorized();
        }

        emit ValidatorDequeued(validator.pubKey);

        delete validator.node;
        delete validator.pubKey;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getNodeEnclaveMeasurements() public view returns (bytes32, bytes32) {
        return (_mrenclave, _mrsigner);
    }

    function _buildNodeRaveCommitment(ValidatorKeyData calldata data, address withdrawalCredentials)
        public
        view
        returns (bytes32)
    {
        ValidatorRaveData memory raveData = ValidatorRaveData({
            pubKey: data.blsPubKey,
            signature: data.signature,
            depositDataRoot: data.depositDataRoot,
            blsEncryptedPrivKeyShares: data.blsEncryptedPrivKeyShares,
            blsPubKeyShares: data.blsPubKeyShares
        });

        Safe guardians = POOL.GUARDIANS();

        return keccak256(
            abi.encode(
                raveData,
                withdrawalCredentials,
                POOL.getGuardianModule().getGuardiansEnclaveAddresses(guardians),
                guardians.getThreshold()
            )
        );
    }

    function _validateGuardianSignatures(
        bytes memory pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) internal view {
        bytes32 msgToBeSigned = getMessageToBeSigned(pubKey, signature, depositDataRoot);

        Safe guardians = POOL.GUARDIANS();

        address[] memory enclaveAddresses = POOL.getGuardianModule().getGuardiansEnclaveAddresses(guardians);
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

    function getValidatorInfo(uint256 validatorIndex) external view returns (Validator memory) {
        return _validators[validatorIndex];
    }

    function getEnclaveVerifier() external view returns (IEnclaveVerifier) {
        return _enclaveVerifier;
    }

    function setNodeEnclaveMeasurements(bytes32 mrenclave, bytes32 mrsigner) external {
        // TODO: onlyowner
        bytes32 oldMrenclave = _mrenclave;
        bytes32 oldMrsigner = _mrsigner;
        _mrenclave = mrenclave;
        _mrsigner = mrsigner;
        emit NodeEnclaveMeasurementsChanged(oldMrenclave, mrenclave, oldMrsigner, mrsigner);
    }

    function getMessageToBeSigned(bytes memory pubKey, bytes calldata signature, bytes32 depositDataRoot)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(pubKey, POOL.getWithdrawalPool(), signature, depositDataRoot, _expectCustody(pubKey))
        ).toEthSignedMessageHash();
    }

    function _expectCustody(bytes memory pubKey) internal view returns (bool) {
        // return _eigenPodProxies[address(eigenPodProxy)].validatorInformation[keccak256(pubKey)].bond
        //     != _nonCustodialBondRequirement;

        return true;
    }

    function _getWithdrawalCredentials() internal view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), POOL.getWithdrawalPool());
    }

    // checks that enough encrypted private keyshares + public keyshares were supplied for each guardian to receive one. Also verify that the raveEvidence is valid and contained the expected and fresh raveCommitment.
    function _verifyKeyRequirements(ValidatorKeyData calldata data, bytes32 raveCommitment) internal view {
        // Validate enough keyshares supplied for all guardians
        uint256 numGuardians = POOL.GUARDIANS().getOwners().length;
        if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeyShares.length != numGuardians) {
            revert InvalidBLSPublicKeyShares();
        }

        // Use RAVE to verify remote attestation evidence
        bool custodyVerified = _enclaveVerifier.verifyEvidence({
            blockNumber: data.blockNumber,
            raveCommitment: raveCommitment,
            evidence: data.evidence,
            mrenclave: _mrenclave,
            mrsigner: _mrsigner
        });

        if (!custodyVerified) {
            revert CouldNotVerifyCustody();
        }
    }
}
