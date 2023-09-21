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
import { IPufferServiceManager } from "puffer/interface/IPufferServiceManager.sol";
import { PufferServiceManagerStorage } from "puffer/PufferServiceManagerStorage.sol";
import { OwnableUpgradeable } from "openzeppelin-upgradeable/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";

/**
 * @title PufferServiceManager
 * @author Puffer Finance
 * @notice PufferServiceManager TODO:
 * @custom:security-contact security@puffer.fi
 */
contract PufferServiceManager is
    IPufferServiceManager,
    OwnableUpgradeable,
    UUPSUpgradeable,
    PufferServiceManagerStorage
{
    using ECDSA for bytes32;

    /**
     * @dev BLS public keys are 48 bytes long
     */
    uint256 internal constant _BLS_PUB_KEY_LENGTH = 48;

    uint256 internal constant _4_ETHER = 4 ether;

    uint256 internal constant _2_ETHER = 2 ether;

    /**
     * @notice Puffer Pool
     */
    PufferPool public POOL;

    /**
     * @dev Guardians multisig wallet
     */
    Safe public GUARDIANS;

    /**
     * @dev Puffer finance treasury
     */
    address payable public immutable TREASURY;

    /**
     * @dev EigenLayer's Strategy Manager
     */
    IStrategyManager public immutable EIGEN_STRATEGY_MANAGER;

    /**
     * @dev Allow a call from guardians multisig
     */
    modifier onlyGuardians() {
        _onlyGuardians();
        _;
    }

    constructor(Safe guardians, address payable treasury, IStrategyManager eigenStrategyManager) {
        TREASURY = treasury;
        GUARDIANS = guardians;
        EIGEN_STRATEGY_MANAGER = eigenStrategyManager;
        _disableInitializers();
    }

    function initialize(
        PufferPool pool,
        address enclaveVerifier,
        address withdrawalPool,
        address executionRewardsVault,
        address consensusVault,
        address guardianSafeModule
    ) external initializer {
        __Ownable_init();
        _setEnclaveVerifier(enclaveVerifier);
        _setProtocolFeeRate(5 * FixedPointMathLib.WAD); // 5%
        POOL = pool;
        _withdrawalPool = withdrawalPool;
        _executionRewardsVault = executionRewardsVault;
        _consensusVault = consensusVault;
        _guardianModule = GuardianModule(guardianSafeModule);
    }

    function setProtocolFeeRate(uint256 protocolFeeRate) external onlyOwner {
        _setProtocolFeeRate(protocolFeeRate);
    }

    function setGuardianEnclaveMeasurements(bytes32 guardianMrenclave, bytes32 guardianMrsigner) external onlyOwner {
        bytes32 oldMrenclave = _guardianMrenclave;
        bytes32 oldMrsigner = _guardianMrsigner;
        _guardianMrenclave = guardianMrenclave;
        _guardianMrsigner = guardianMrsigner;
        emit GuardianNodeEnclaveMeasurementsChanged(oldMrenclave, guardianMrenclave, oldMrsigner, guardianMrsigner);
    }

    function _setProtocolFeeRate(uint256 protocolFee) internal {
        uint256 oldProtocolFee = _protocolFeeRate;
        _protocolFeeRate = protocolFee;
        emit ProtocolFeeRateChanged(oldProtocolFee, protocolFee);
    }

    function _setEnclaveVerifier(address enclaveVerifier) internal {
        _enclaveVerifier = IEnclaveVerifier(enclaveVerifier);
        emit EnclaveVerifierChanged(enclaveVerifier);
    }

    function _onlyGuardians() internal view {
        if (msg.sender != address(GUARDIANS)) {
            revert Unauthorized();
        }
    }

    function registerValidatorKey(ValidatorKeyData calldata data) external {
        // Sanity check on blsPubKey
        if (data.blsPubKey.length != _BLS_PUB_KEY_LENGTH) {
            revert InvalidBLSPubKey();
        }

        // Verify enclave remote attestation evidence
        if (data.evidence.report.length > 0) {
            bytes32 raveCommitment = _buildNodeRaveCommitment(data, _withdrawalPool);
            _verifyKeyRequirements(data, raveCommitment);
        }

        uint256 validatorBondRequirement = data.evidence.report.length > 0 ? _4_ETHER : _2_ETHER;
        // TODO: check if the msg.sender has enough ETH as a bond

        // To prevent spamming the queue
        // PufferAVS.isEligibleForRegisteringValidatorKey(msg.sender, data);

        // PufferAVS logic

        // 1. make sure that the node operator is opted to our AVS
        // 2. make sure that he has enough WETH delegated

        Validator memory validator;
        validator.pubKey = data.blsPubKey;
        validator.node = msg.sender;

        _validators[pendingValidatorIndex] = validator;

        ++pendingValidatorIndex;

        emit ValidatorKeyRegistered(data.blsPubKey);
    }

    /**
     * @dev We need to have this wrapper in order to modify the state of the contract if the provisionNodeETH reverts
     */
    function provisionNodeETHWrapper(
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external {
        uint256 index = validatorIndexToBeProvisionedNext;

        ++validatorIndexToBeProvisionedNext;

        Validator memory validator = _validators[index];

        try this.provisionNodeETH(index, validator, signature, depositDataRoot, guardianEnclaveSignatures) {
            emit SuccesfullyProvisioned(validator.pubKey);
        } catch {
            emit FailedToProvision(validator.pubKey);
        }
    }

    // @audit-info be super careful with this and DOS attack
    function provisionNodeETH(
        uint256 index,
        Validator memory validator,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external {
        require(msg.sender == address(this));

        if (validator.status != Status.PENDING) {
            revert InvalidValidatorState();
        }

        // TODO: we need to check that the node operator has enough WETH delegated and that it is opted to our AVS

        // Validate guardian signatures
        _guardianModule.validateGuardianSignatures({
            pubKey: validator.pubKey,
            guardianEnclaveSignatures: guardianEnclaveSignatures,
            signature: signature,
            depositDataRoot: depositDataRoot
        });

        _validators[index].status = Status.ACTIVE;

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

    function getValidatorsAddresses() external view returns (address[] memory) {
        uint256 numOfValidators = validatorIndexToBeProvisionedNext + 1;

        address[] memory addresses = new address[](numOfValidators);

        for (uint256 i = numOfValidators; i > 0; i--) {
            addresses[i] = _validators[i].node;
        }

        return addresses;
    }

    function stopRegistration(uint256 validatorIndex) external {
        // `msg.sender` is the Node Operator
        Validator storage validator = _validators[validatorIndex];

        if (validator.status != Status.PENDING) {
            revert InvalidValidatorState();
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

        return keccak256(
            abi.encode(
                raveData,
                withdrawalCredentials,
                _guardianModule.getGuardiansEnclaveAddresses(GUARDIANS),
                GUARDIANS.getThreshold()
            )
        );
    }

    function getValidatorInfo(uint256 validatorIndex) external view returns (Validator memory) {
        return _validators[validatorIndex];
    }

    function setNodeEnclaveMeasurements(bytes32 mrenclave, bytes32 mrsigner) external {
        // TODO: onlyowner
        bytes32 oldMrenclave = _mrenclave;
        bytes32 oldMrsigner = _mrsigner;
        _mrenclave = mrenclave;
        _mrsigner = mrsigner;
        emit NodeEnclaveMeasurementsChanged(oldMrenclave, mrenclave, oldMrsigner, mrsigner);
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function setExecutionCommission(uint256 newValue) external onlyOwner {
        _setExecutionCommission(newValue);
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function setConsensusCommission(uint256 newValue) external onlyOwner {
        _setConsensusCommission(newValue);
    }

    function _setExecutionCommission(uint256 newValue) internal {
        uint256 oldValue = _executionCommission;
        _executionCommission = newValue;
        emit ExecutionCommissionChanged(oldValue, newValue);
    }

    function _setConsensusCommission(uint256 newValue) internal {
        uint256 oldValue = _consensusCommission;
        _consensusCommission = newValue;
        emit ConsensusCommissionChanged(oldValue, newValue);
    }

    function _getWithdrawalCredentials() internal view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), _withdrawalPool);
    }

    // checks that enough encrypted private keyshares + public keyshares were supplied for each guardian to receive one. Also verify that the raveEvidence is valid and contained the expected and fresh raveCommitment.
    function _verifyKeyRequirements(ValidatorKeyData calldata data, bytes32 raveCommitment) internal view {
        // Validate enough keyshares supplied for all guardians
        uint256 numGuardians = GUARDIANS.getOwners().length;
        if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeyShares.length != numGuardians) {
            revert InvalidBLSPublicKeyShares();
        }

        // @todo Possibly remove
        // Use RAVE to verify remote attestation evidence
        // bool custodyVerified = _enclaveVerifier.verifyEvidence({
        //     blockNumber: data.blockNumber,
        //     raveCommitment: raveCommitment,
        //     evidence: data.evidence,
        //     mrenclave: _mrenclave,
        //     mrsigner: _mrsigner
        // });

        // if (!custodyVerified) {
        //     revert CouldNotVerifyCustody();
        // }
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getWithdrawalPool() external view returns (address) {
        return _withdrawalPool;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getConsensusVault() external view returns (address) {
        return _consensusVault;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getExecutionRewardsVault() external view returns (address) {
        return _executionRewardsVault;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getExecutionCommission() external view returns (uint256) {
        return _executionCommission;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getGuardianEnclaveMeasurements() external view returns (bytes32, bytes32) {
        return (_guardianMrenclave, _guardianMrsigner);
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getGuardianModule() external view returns (GuardianModule) {
        return _guardianModule;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getConsensusCommission() external view returns (uint256) {
        return _consensusCommission;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getProtocolFeeRate() external view returns (uint256) {
        return _protocolFeeRate;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getEnclaveVerifier() external view returns (IEnclaveVerifier) {
        return _enclaveVerifier;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner { }
}
