// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Status } from "puffer/struct/Status.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferServiceManager } from "puffer/interface/IPufferServiceManager.sol";
import { PufferServiceManagerStorage } from "puffer/PufferServiceManagerStorage.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
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
    AccessManagedUpgradeable,
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

    uint32 internal constant _MAX_UINT_32 = ~uint32(0);

    /**
     * @dev Puffer finance treasury
     */
    address payable public immutable TREASURY;

    /**
     * @notice Guardians {Safe} multisig
     */
    Safe public immutable GUARDIANS;

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
        address accessManager,
        PufferPool pool,
        address withdrawalPool,
        address executionRewardsVault,
        address consensusVault,
        address guardianSafeModule
    ) external initializer {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();
        __AccessManaged_init(accessManager);
        _setProtocolFeeRate(5 * FixedPointMathLib.WAD); // 5%
        $.pool = pool;
        $.withdrawalPool = withdrawalPool;
        $.executionRewardsVault = executionRewardsVault;
        $.consensusVault = consensusVault;
        $.guardianModule = GuardianModule(guardianSafeModule);
    }

    function setExecutionRewardsCommitment(uint256 ethAmount) external {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();
        uint256 oldCommitment = $.executionRewardsCommitment;
        $.executionRewardsCommitment = ethAmount;
        emit ExecutionRewardsCommitmentChanged(oldCommitment, ethAmount);
    }

    function setProtocolFeeRate(uint256 protocolFeeRate) external restricted {
        _setProtocolFeeRate(protocolFeeRate);
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

    function registerValidatorKey(ValidatorKeyData calldata data) external payable {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        if (data.blsPubKey.length != _BLS_PUB_KEY_LENGTH) {
            revert InvalidBLSPubKey();
        }

        // Forward ETH to PufferPool
        $.pool.depositETHWithoutMinting{value: msg.value}();

        uint256 numGuardians = GUARDIANS.getOwners().length;

        if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeyShares.length != numGuardians) {
            revert InvalidBLSPublicKeyShares();
        }

        uint256 validatorBondRequirement = data.raveEvidence.length > 0 ? _4_ETHER : _2_ETHER;

        if (msg.value != $.executionRewardsCommitment) {
            revert InvalidETHAmount();
        }


        //@todo AVS logic
        // 1. make sure that the node operator is opted to our AVS
        // 2. make sure that he has enough WETH delegated

        Validator memory validator;
        validator.pubKey = data.blsPubKey;
        validator.status = Status.PENDING;
        validator.node = msg.sender;

        uint256 validatorIndex = $.pendingValidatorIndex;
        $.validators[validatorIndex] = validator;

        ++$.pendingValidatorIndex;

        emit ValidatorKeyRegistered(data.blsPubKey, validatorIndex);
    }

    function getPendingValidatorIndex() external view returns (uint256) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();
        return $.pendingValidatorIndex;
    }

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

        try this.provisionNodeETH({
            index: index,
            validator: validator,
            signature: signature,
            depositDataRoot: depositDataRoot,
            guardianEnclaveSignatures: guardianEnclaveSignatures
        }) {
            emit SuccesfullyProvisioned(validator.pubKey, index);
        } catch {
            emit FailedToProvision(validator.pubKey, index);
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
            withdrawalCredentials: getWithdrawalCredentials(),
            signature: signature,
            depositDataRoot: depositDataRoot
        });
    }

    function getValidators() external view returns (bytes[] memory) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        uint256 numOfValidators = $.validatorIndexToBeProvisionedNext;

        bytes[] memory validators = new bytes[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; i++) {
            validators[i] = bytes($.validators[i].pubKey);
        }

        return validators;
    }

    function getValidatorsAddresses() external view returns (address[] memory) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        uint256 numOfValidators = $.validatorIndexToBeProvisionedNext;

        address[] memory addresses = new address[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; i++) {
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

        // Update the status to DEQUEUED
        validator.status = Status.DEQUEUED;

        emit ValidatorDequeued(validator.pubKey, validatorIndex);
    }

    function getValidatorInfo(uint256 validatorIndex) external view returns (Validator memory) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.validators[validatorIndex];
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function setExecutionCommission(uint256 newValue) external restricted {
        _setExecutionCommission(newValue);
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function setConsensusCommission(uint256 newValue) external restricted {
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

    function getWithdrawalCredentials() public view returns (bytes memory) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), $.withdrawalPool);
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
        return GUARDIANS;
    }

    /**
     * @inheritdoc IPufferServiceManager
     */
    function getProtocolFeeRate() external view returns (uint256) {
        ServiceManagerStorage storage $ = _getPufferServiceManagerStorage();

        return $.protocolFeeRate;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted {}
}
