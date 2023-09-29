// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Status } from "puffer/struct/Status.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferStrategy } from "puffer/PufferStrategy.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";

/**
 * @title PufferProtocol
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferProtocol is IPufferProtocol, AccessManagedUpgradeable, UUPSUpgradeable, PufferProtocolStorage {
    using ECDSA for bytes32;

    error Create2Failed();

    error InvalidPufferStrategy();

    event NewPufferStrategyCreated(address strategy);

    /**
     * @dev BLS public keys are 48 bytes long
     */
    uint256 internal constant _BLS_PUB_KEY_LENGTH = 48;

    uint256 internal constant _4_ETHER = 4 ether;

    uint256 internal constant _2_ETHER = 2 ether;

    /**
     * @notice Address of the PufferStrategy proxy beacon
     */
    address public immutable PUFFER_STRATEGY_BEACON;

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

    constructor(
        Safe guardians,
        address payable treasury,
        IStrategyManager eigenStrategyManager,
        address strategyBeacon
    ) {
        PUFFER_STRATEGY_BEACON = strategyBeacon;
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
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        __AccessManaged_init(accessManager);
        _setProtocolFeeRate(5 * FixedPointMathLib.WAD); // 5%
        $.noRestakingStrategy = PufferStrategy(payable(_createPufferStrategy(bytes32("NO_RESTAKING"))));
        $.pool = pool;
        $.withdrawalPool = withdrawalPool;
        $.executionRewardsVault = executionRewardsVault;
        $.consensusVault = consensusVault;
        $.guardianModule = GuardianModule(guardianSafeModule);
    }

    function createPufferStrategy(bytes32 strategyName) external restricted returns (address) {
        return _createPufferStrategy(strategyName);
    }

    function getDefaultStrategy() external view returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return address($.noRestakingStrategy);
    }

    function _createPufferStrategy(bytes32 strategyName) internal returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        PufferStrategy strategy = _createNewPufferStrategy(strategyName);
        $.strategies[strategyName] = strategy;
        emit NewPufferStrategyCreated(address(strategy));
        return address(strategy);
    }

    function _createNewPufferStrategy(bytes32 salt) internal returns (PufferStrategy strategy) {
        bytes memory deploymentData = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(PUFFER_STRATEGY_BEACON, abi.encodeCall(PufferStrategy.initialize, (this)))
        );

        // solhint-disable-next-line no-inline-assembly
        assembly {
            strategy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), salt)
        }

        if (address(strategy) == address(0)) {
            revert Create2Failed();
        }

        return PufferStrategy(payable(address(strategy)));
    }

    function setExecutionRewardsCommitment(uint256 ethAmount) external restricted {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldCommitment = $.executionRewardsCommitment;
        $.executionRewardsCommitment = ethAmount;
        emit ExecutionRewardsCommitmentChanged(oldCommitment, ethAmount);
    }

    function setProtocolFeeRate(uint256 protocolFeeRate) external restricted {
        _setProtocolFeeRate(protocolFeeRate);
    }

    function _setProtocolFeeRate(uint256 protocolFee) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 oldProtocolFee = $.protocolFeeRate;
        $.protocolFeeRate = protocolFee;
        emit ProtocolFeeRateChanged(oldProtocolFee, protocolFee);
    }

    function _onlyGuardians() internal view {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        if (msg.sender != address($.guardians)) {
            revert Unauthorized();
        }
    }

    function registerValidatorKey(ValidatorKeyData calldata data, bytes32 strategyName) external payable {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        if (data.blsPubKey.length != _BLS_PUB_KEY_LENGTH) {
            revert InvalidBLSPubKey();
        }

        address strategy = address($.strategies[strategyName]);

        if (strategy == address(0)) {
            revert InvalidPufferStrategy();
        }

        uint256 executionRewardsCommitment = $.executionRewardsCommitment;

        PufferPool pool = $.pool;

        uint256 minted = pool.depositETH{ value: msg.value - executionRewardsCommitment }();

        // Forward ETH to PufferPool
        pool.depositETHWithoutMinting{ value: executionRewardsCommitment }();

        uint256 numGuardians = GUARDIANS.getOwners().length;

        if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeyShares.length != numGuardians) {
            revert InvalidBLSPublicKeyShares();
        }

        uint256 validatorBondRequirement = data.raveEvidence.length > 0 ? _2_ETHER : _4_ETHER;

        if (msg.value != $.executionRewardsCommitment + validatorBondRequirement) {
            revert InvalidETHAmount();
        }

        //@todo AVS logic
        // 1. make sure that the node operator is opted to our AVS
        // 2. make sure that he has enough WETH delegated

        Validator memory validator;
        validator.pubKey = data.blsPubKey;
        validator.status = Status.PENDING;
        validator.strategy = strategy;
        validator.node = msg.sender;
        validator.pufETHBond = minted;

        uint256 validatorIndex = $.pendingValidatorIndex;
        $.validators[validatorIndex] = validator;

        ++$.pendingValidatorIndex;

        emit ValidatorKeyRegistered(data.blsPubKey, validatorIndex);
    }

    function getPendingValidatorIndex() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
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
        ProtocolStorage storage $ = _getPufferProtocolStorage();

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

        ProtocolStorage storage $ = _getPufferProtocolStorage();

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
            withdrawalCredentials: getWithdrawalCredentials($.validators[index].strategy),
            signature: signature,
            depositDataRoot: depositDataRoot
        });
    }

    function getValidators() external view returns (bytes[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 numOfValidators = $.validatorIndexToBeProvisionedNext;

        bytes[] memory validators = new bytes[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; i++) {
            validators[i] = bytes($.validators[i].pubKey);
        }

        return validators;
    }

    function getValidatorsAddresses() external view returns (address[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 numOfValidators = $.validatorIndexToBeProvisionedNext;

        address[] memory addresses = new address[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; i++) {
            addresses[i] = $.validators[i].node;
        }

        return addresses;
    }

    function stopRegistration(uint256 validatorIndex) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

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
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        return $.validators[validatorIndex];
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function setExecutionCommission(uint256 newValue) external restricted {
        _setExecutionCommission(newValue);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function setConsensusCommission(uint256 newValue) external restricted {
        _setConsensusCommission(newValue);
    }

    function _setExecutionCommission(uint256 newValue) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 oldValue = $.executionCommission;
        $.executionCommission = newValue;
        emit ExecutionCommissionChanged(oldValue, newValue);
    }

    function _setConsensusCommission(uint256 newValue) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 oldValue = $.consensusCommission;
        $.consensusCommission = newValue;
        emit ConsensusCommissionChanged(oldValue, newValue);
    }

    function getWithdrawalCredentials(address strategy) public view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), strategy);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getWithdrawalPool() external view returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        return $.withdrawalPool;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getConsensusVault() external view returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        return $.consensusVault;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getExecutionRewardsVault() external view returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        return $.executionRewardsVault;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getExecutionCommission() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        return $.executionCommission;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getGuardianModule() external view returns (GuardianModule) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        return $.guardianModule;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getConsensusCommission() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        return $.consensusCommission;
    }

    function getGuardians() external view returns (Safe) {
        return GUARDIANS;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getProtocolFeeRate() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        return $.protocolFeeRate;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
