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
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/**
 * @title PufferProtocol
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferProtocol is IPufferProtocol, AccessManagedUpgradeable, UUPSUpgradeable, PufferProtocolStorage {
    using ECDSA for bytes32;
    using SafeTransferLib for address;
    using SafeTransferLib for address payable;

    /**
     * @dev BLS public keys are 48 bytes long
     */
    uint256 internal constant _BLS_PUB_KEY_LENGTH = 48;

    uint256 internal constant _4_ETHER = 4 ether;

    uint256 internal constant _2_ETHER = 2 ether;

    /**
     * @dev Number of blocks
     * 1800 * 12(avg block time) = 21600 seconds
     * 21600 seconds = 6 hours
     */
    uint256 internal constant _UPDATE_INTERVAL = 1800;

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
        if (msg.sender != address(GUARDIANS)) {
            revert Unauthorized();
        }
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

    function initialize(address accessManager, PufferPool pool, address withdrawalPool, address guardianSafeModule)
        external
        initializer
    {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        __AccessManaged_init(accessManager);
        _setProtocolFeeRate(2 * FixedPointMathLib.WAD); // 2%
        $.noRestakingStrategy = PufferStrategy(payable(_createPufferStrategy(bytes32("NO_RESTAKING"))));
        $.pool = pool;
        $.withdrawalPool = withdrawalPool;
        $.guardianModule = GuardianModule(guardianSafeModule);
        $.guardiansFeeRate = 5 * 1e17; // 0.5 %
        $.withdrawalPoolRate = 10 * FixedPointMathLib.WAD; // 10 %
    }

    function createPufferStrategy(bytes32 strategyName) external restricted returns (address) {
        return _createPufferStrategy(strategyName);
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

        uint256 smoothingCommitment = $.smoothingCommitment;

        uint256 numGuardians = GUARDIANS.getOwners().length;

        if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeyShares.length != numGuardians) {
            revert InvalidBLSPublicKeyShares();
        }

        if (msg.value != smoothingCommitment) {
            revert InvalidETHAmount();
        }

        Validator memory validator;
        validator.pubKey = data.blsPubKey;
        validator.status = Status.PENDING;
        validator.strategy = strategy;
        validator.commitmentAmount = uint72(smoothingCommitment);
        validator.lastCommitmentPayment = uint40(block.timestamp);
        validator.node = msg.sender;

        uint256 validatorIndex = $.pendingValidatorIndex;
        $.validators[validatorIndex] = validator;

        ++$.pendingValidatorIndex;

        emit ValidatorKeyRegistered(data.blsPubKey, validatorIndex);

        _transferFunds($);
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

        bytes memory withdrawalCredentials = getWithdrawalCredentials($.validators[index].strategy);

        // Validate guardian signatures
        $.guardianModule.validateGuardianSignatures({
            pubKey: validator.pubKey,
            guardianEnclaveSignatures: guardianEnclaveSignatures,
            signature: signature,
            withdrawalCredentials: withdrawalCredentials,
            depositDataRoot: depositDataRoot
        });

        $.validators[index].status = Status.ACTIVE;

        emit ETHProvisioned(validator.node, validator.pubKey, block.timestamp);

        $.pool.createValidator({
            pubKey: validator.pubKey,
            withdrawalCredentials: withdrawalCredentials,
            signature: signature,
            depositDataRoot: depositDataRoot
        });
    }

    function extendCommitment(uint256 validatorIndex) external payable {
        //@todo logic.. tests
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        Validator storage validator = $.validators[validatorIndex];

        validator.lastCommitmentPayment = uint40(block.timestamp);
        // validator.lastP

        // emit SmoothingCommitmentPaid(validator.node, block.timestamp, msg.value);
        _transferFunds($);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
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

    function updateBacking(uint256 ethAmount, uint256 lockedETH, uint256 pufETHTotalSupply, uint256 blockNumber)
        external
        restricted
    {
        PufferPoolStorage storage $ = _getPuferPoolStorage();
        //@audit figure out if we want more restrictions on this
        if (block.number < blockNumber) {
            revert InvalidData();
        }

        if (block.number - $.lastUpdate < _UPDATE_INTERVAL) {
            revert InvalidData();
        }

        $.ethAmount = ethAmount;
        $.lockedETH = lockedETH;
        $.pufETHTotalSupply = pufETHTotalSupply;
        $.lastUpdate = blockNumber;

        emit BackingUpdated(ethAmount, lockedETH, pufETHTotalSupply, blockNumber);
    }

    function setCommitment(uint256 smoothingCommitment) external restricted {
        _setCommitment(smoothingCommitment);
    }

    function setProtocolFeeRate(uint256 protocolFeeRate) external restricted {
        _setProtocolFeeRate(protocolFeeRate);
    }
    /**
     * @inheritdoc IPufferProtocol
     */

    function getDefaultStrategy() external view returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return address($.noRestakingStrategy);
    }
    /**
     * @inheritdoc IPufferProtocol
     */

    function getValidatorsAddresses() external view returns (address[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 numOfValidators = $.validatorIndexToBeProvisionedNext;

        address[] memory addresses = new address[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; i++) {
            addresses[i] = $.validators[i].node;
        }

        return addresses;
    }
    /**
     * @inheritdoc IPufferProtocol
     */

    function getValidators() external view returns (bytes[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 numOfValidators = $.validatorIndexToBeProvisionedNext;

        bytes[] memory validators = new bytes[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; i++) {
            validators[i] = bytes($.validators[i].pubKey);
        }

        return validators;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getPendingValidatorIndex() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.pendingValidatorIndex;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getValidatorInfo(uint256 validatorIndex) external view returns (Validator memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.validators[validatorIndex];
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
    function getGuardianModule() external view returns (GuardianModule) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.guardianModule;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getProtocolFeeRate() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.protocolFeeRate;
    }

    function _setCommitment(uint256 smoothingCommitment) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldSmoothingCommitment = $.smoothingCommitment;
        $.smoothingCommitment = smoothingCommitment;
        emit CommitmentChanged(oldSmoothingCommitment, smoothingCommitment);
    }

    function _transferFunds(ProtocolStorage storage $) internal {
        uint256 treasuryAmount = _sendETH(TREASURY, $.protocolFeeRate);
        uint256 withdrawalPoolAmount = _sendETH($.withdrawalPool, $.withdrawalPoolRate);
        uint256 guardiansAmount = _sendETH(address(GUARDIANS), $.guardiansFeeRate);

        uint256 poolAmount = msg.value - (treasuryAmount + withdrawalPoolAmount + guardiansAmount);
        $.pool.paySmoothingCommitment{ value: poolAmount }();
    }

    function _sendETH(address to, uint256 rate) internal returns (uint256 amount) {
        amount = FixedPointMathLib.fullMulDiv(msg.value, rate, _ONE_HUNDRED_WAD);

        if (amount != 0) {
            to.safeTransferETH(amount);
        }

        return amount;
    }

    function _setProtocolFeeRate(uint256 protocolFee) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldProtocolFee = $.protocolFeeRate;
        $.protocolFeeRate = protocolFee;
        emit ProtocolFeeRateChanged(oldProtocolFee, protocolFee);
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

    function getWithdrawalCredentials(address strategy) public pure returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), strategy);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
