// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { ValidatorRaveData } from "puffer/struct/ValidatorRaveData.sol";
import { ValidatorEnclaveKeyData } from "puffer/struct/ValidatorEnclaveKeyData.sol";
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
import { IServiceManager } from "eigenlayer/interfaces/IServiceManager.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";

/**
 * @title PufferServiceManager
 * @author Puffer Finance
 * @notice PufferServiceManager TODO:
 * @custom:security-contact security@puffer.fi
 */
contract PufferServiceManager is
    IServiceManager,
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
     * @dev Puffer finance treasury
     */
    address payable public immutable TREASURY;

    /**
     * @dev EigenLayer's Strategy Manager
     */
    IStrategyManager public immutable EIGEN_STRATEGY_MANAGER;

    /**
     * @dev EigenLayer's Slasher
     */
    ISlasher public immutable SLASHER;

    /**
     * @dev Allow a call from guardians multisig
     */
    modifier onlyGuardians() {
        _onlyGuardians();
        _;
    }

    constructor(Safe guardians, address payable treasury, IStrategyManager eigenStrategyManager, ISlasher slasher) {
        TREASURY = treasury;
        guardians = guardians;
        EIGEN_STRATEGY_MANAGER = eigenStrategyManager;
        SLASHER = slasher;
        _disableInitializers();
    }

    function initialize(
        PufferPool pool,
        address withdrawalPool,
        address executionRewardsVault,
        address consensusVault,
        address guardianSafeModule
    ) external initializer {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        __Ownable_init();
        _setProtocolFeeRate(5 * FixedPointMathLib.WAD); // 5%
        $.pool = pool;
        $.withdrawalPool = withdrawalPool;
        $.executionRewardsVault = executionRewardsVault;
        $.consensusVault = consensusVault;
        $.guardianModule = GuardianModule(guardianSafeModule);
    }

    function owner() public view override(OwnableUpgradeable, IServiceManager) returns (address) {
        return this.owner();
    }

    // Cheyenne TODO: Implement
    function taskNumber() external view returns (uint32) { }

    function freezeOperator(address operator) external onlyGuardians {
        SLASHER.freezeOperator(operator);
    }

    function recordFirstStakeUpdate(address operator, uint32 serveUntilBlock) external onlyGuardians {
        SLASHER.recordFirstStakeUpdate(operator, serveUntilBlock);
    }

    /**
     * @dev Unused, but exposing for interface compatibility
     */
    function recordStakeUpdate(address operator, uint32 updateBlock, uint32 serveUntilBlock, uint256 prevElement)
        external
    { }

    function recordLastStakeUpdateAndRevokeSlashingAbility(address operator, uint32 serveUntilBlock)
        external
        onlyGuardians
    {
        SLASHER.recordLastStakeUpdateAndRevokeSlashingAbility(operator, serveUntilBlock);
    }

    // Cheyenne TODO: Implement
    function latestServeUntilBlock() external view returns (uint32) { }

    function setProtocolFeeRate(uint256 protocolFeeRate) external onlyOwner {
        _setProtocolFeeRate(protocolFeeRate);
    }

    function setGuardianEnclaveMeasurements(bytes32 guardianMrenclave, bytes32 guardianMrsigner) external onlyOwner {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        bytes32 oldMrenclave = $.guardianMrenclave;
        bytes32 oldMrsigner = $.guardianMrsigner;
        $.guardianMrenclave = guardianMrenclave;
        $.guardianMrsigner = guardianMrsigner;
        emit GuardianNodeEnclaveMeasurementsChanged(oldMrenclave, guardianMrenclave, oldMrsigner, guardianMrsigner);
    }

    function _setProtocolFeeRate(uint256 protocolFee) internal {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        uint256 oldProtocolFee = $.protocolFeeRate;
        $.protocolFeeRate = protocolFee;
        emit ProtocolFeeRateChanged(oldProtocolFee, protocolFee);
    }

    function _onlyGuardians() internal view {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        if (msg.sender != address($.guardians)) {
            revert Unauthorized();
        }
    }

    function registerValidatorKey(ValidatorKeyData calldata data) external {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        // Sanity check on blsPubKey
        if (data.blsPubKey.length != _BLS_PUB_KEY_LENGTH) {
            revert InvalidBLSPubKey();
        }

        // Verify enclave remote attestation evidence
        if (data.evidence.report.length > 0) {
            // Validate enough keyshares supplied for all guardians
            uint256 numGuardians = $.guardians.getOwners().length;

            if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
                revert InvalidBLSPrivateKeyShares();
            }

            if (data.blsPubKeyShares.length != numGuardians) {
                revert InvalidBLSPublicKeyShares();
            }
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

        $.validators[$.pendingValidatorIndex] = validator;

        ++$.pendingValidatorIndex;

        emit ValidatorKeyRegistered(data.blsPubKey);
    }

    // Cheyenne TODO: Implement
    function registerEnclaveValidatorKey(ValidatorEnclaveKeyData calldata data) external { }

    /**
     * @dev We need to have this wrapper in order to modify the state of the contract if the provisionNodeETH reverts
     */
    function provisionNodeETHWrapper(
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        uint256 index = $.validatorIndexToBeProvisionedNext;

        ++$.validatorIndexToBeProvisionedNext;

        Validator memory validator = $.validators[index];

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

        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        if (validator.status != Status.PENDING) {
            revert InvalidValidatorState();
        }

        // TODO: we need to check that the node operator has enough WETH delegated and that it is opted to our AVS

        // Validate guardian signatures
        $.guardianModule.validateGuardianSignatures({
            pubKey: validator.pubKey,
            guardianEnclaveSignatures: guardianEnclaveSignatures,
            signature: signature,
            depositDataRoot: depositDataRoot
        });

        $.validators[index].status = Status.ACTIVE;

        emit ETHProvisioned(validator.node, validator.pubKey, block.timestamp);

        $.pool.createValidator({
            pubKey: validator.pubKey,
            withdrawalCredentials: _getWithdrawalCredentials(),
            signature: signature,
            depositDataRoot: depositDataRoot
        });
    }

    function getValidators() external view returns (bytes[] memory) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        uint256 numOfValidators = $.validatorIndexToBeProvisionedNext + 1;

        bytes[] memory validators = new bytes[](numOfValidators);

        for (uint256 i = numOfValidators; i > 0; i--) {
            validators[i] = bytes($.validators[i].pubKey);
        }

        return validators;
    }

    function getValidatorsAddresses() external view returns (address[] memory) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        uint256 numOfValidators = $.validatorIndexToBeProvisionedNext + 1;

        address[] memory addresses = new address[](numOfValidators);

        for (uint256 i = numOfValidators; i > 0; i--) {
            addresses[i] = $.validators[i].node;
        }

        return addresses;
    }

    function stopRegistration(uint256 validatorIndex) external {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        // `msg.sender` is the Node Operator
        Validator storage validator = $.validators[validatorIndex];

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
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return ($.mrenclave, $.mrsigner);
    }

    function getValidatorInfo(uint256 validatorIndex) external view returns (Validator memory) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.validators[validatorIndex];
    }

    function setNodeEnclaveMeasurements(bytes32 mrenclave, bytes32 mrsigner) external {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        // TODO: onlyowner
        bytes32 oldMrenclave = $.mrenclave;
        bytes32 oldMrsigner = $.mrsigner;
        $.mrenclave = mrenclave;
        $.mrsigner = mrsigner;
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
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        uint256 oldValue = $.executionCommission;
        $.executionCommission = newValue;
        emit ExecutionCommissionChanged(oldValue, newValue);
    }

    function _setConsensusCommission(uint256 newValue) internal {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        uint256 oldValue = $.consensusCommission;
        $.consensusCommission = newValue;
        emit ConsensusCommissionChanged(oldValue, newValue);
    }

    function _getWithdrawalCredentials() internal view returns (bytes memory) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), $.withdrawalPool);
    }

    // checks that enough encrypted private keyshares + public keyshares were supplied for each guardian to receive one. Also verify that the raveEvidence is valid and contained the expected and fresh raveCommitment.
    function _verifyKeyRequirements(ValidatorKeyData calldata data) internal view {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getWithdrawalPool() external view returns (address) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.withdrawalPool;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getConsensusVault() external view returns (address) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.consensusVault;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getExecutionRewardsVault() external view returns (address) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.executionRewardsVault;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getExecutionCommission() external view returns (uint256) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.executionCommission;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getGuardianEnclaveMeasurements() external view returns (bytes32, bytes32) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return ($.guardianMrenclave, $.guardianMrsigner);
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getGuardianModule() external view returns (GuardianModule) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.guardianModule;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getConsensusCommission() external view returns (uint256) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.consensusCommission;
    }

    function getGuardians() external view returns (Safe) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();
        return $.guardians;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getProtocolFeeRate() external view returns (uint256) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.protocolFeeRate;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner { }
}
