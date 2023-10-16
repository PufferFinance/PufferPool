// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Status } from "puffer/struct/Status.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferStrategy } from "puffer/PufferStrategy.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { SafeCastLib } from "solady/utils/SafeCastLib.sol";

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

    /**
     * @dev ETH Amount required for becoming a Validator
     */
    uint256 internal constant _32_ETHER = 32 ether;

    /**
     * @dev ETH Amount required to be deposited as a bond by node operator
     */
    uint256 internal constant _VALIDATOR_BOND = 1 ether;

    /**
     * @dev Default "NO_RESTAKING" strategy
     */
    bytes32 internal constant _NO_RESTAKING = bytes32("NO_RESTAKING");

    /**
     * @dev Number of blocks
     * 50400 * 12(avg block time) = 604800 seconds
     * 604800 seconds ~ 7 days
     */
    uint256 internal constant _UPDATE_INTERVAL = 50400;

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

    function initialize(address accessManager, PufferPool pool, WithdrawalPool withdrawalPool, address guardianSafeModule)
        external
        initializer
    {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        __AccessManaged_init(accessManager);
        _setProtocolFeeRate(2 * FixedPointMathLib.WAD); // 2%
        _setValidatorLimitPerInterval(20);
        bytes32[] memory weights = new bytes32[](1);
        weights[0] = _NO_RESTAKING;
        _setStrategyWeights(weights);
        $.noRestakingStrategy = PufferStrategy(payable(_createPufferStrategy(_NO_RESTAKING)));
        $.pool = pool;
        $.withdrawalPool = withdrawalPool;
        $.guardianModule = GuardianModule(guardianSafeModule);
        $.guardiansFeeRate = 5 * 1e17; // 0.5 %
        $.withdrawalPoolRate = uint64(10 * FixedPointMathLib.WAD); // 10 %
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function registerValidatorKey(ValidatorKeyData calldata data, bytes32 strategyName) external payable {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        _checkValidatorRegistrationInputs(data, strategyName, $);

        uint256 pufETHReceived = $.pool.depositETH{ value: _VALIDATOR_BOND }();

        // Save the validator data to storage
        Validator memory validator;
        validator.pubKey = data.blsPubKey;
        validator.signature = data.signature;
        validator.status = Status.PENDING;
        validator.strategy = address($.strategies[strategyName]);
        validator.bond = pufETHReceived;
        validator.commitmentExpiration = uint40(block.timestamp + 30 days);
        validator.node = msg.sender;

        uint256 validatorIndex = $.pendingValidatorIndicies[strategyName];
        $.validators[strategyName][validatorIndex] = validator;

        // Increment indices for this strategy and number of validators registered
        ++$.pendingValidatorIndicies[strategyName];
        ++$.numberOfValidatorsRegisteredInThisInterval;

        emit ValidatorKeyRegistered(data.blsPubKey, validatorIndex);

        _transferFunds($);
    }

    function getDepositDataRoot(bytes calldata pubKey, bytes calldata signature, bytes calldata withdrawalCredentials)
        external
        view
        returns (bytes32)
    {
        // Copied from the deposit contract
        // https://github.com/ethereum/consensus-specs/blob/dev/solidity_deposit_contract/deposit_contract.sol
        bytes32 pubKeyRoot = sha256(abi.encodePacked(pubKey, bytes16(0)));
        bytes32 signatureRoot = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(signature[:64])), sha256(abi.encodePacked(signature[64:], bytes32(0)))
            )
        );
        return sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(pubKeyRoot, withdrawalCredentials)),
                sha256(abi.encodePacked(_toLittleEndian64(uint64(_32_ETHER)), bytes24(0), signatureRoot))
            )
        );
    }

    function provisionNode(bytes[] calldata guardianEnclaveSignatures) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        (bytes32 strategyName, uint256 index) = getNextValidatorToProvision();

        Validator memory validator = $.validators[strategyName][index];

        _incrementStrategySelectionCounter($, strategyName);

        bytes memory withdrawalCredentials = getWithdrawalCredentials(validator.strategy);

        bytes32 depositDataRoot = this.getDepositDataRoot({
            pubKey: validator.pubKey,
            signature: validator.signature,
            withdrawalCredentials: withdrawalCredentials
        });

        // If the guardian signatures aren't valid this will revert
        $.guardianModule.validateGuardianSignatures({
            pubKey: validator.pubKey,
            guardianEnclaveSignatures: guardianEnclaveSignatures,
            signature: validator.signature,
            withdrawalCredentials: withdrawalCredentials,
            depositDataRoot: depositDataRoot
        });

        $.validators[strategyName][index].status = Status.ACTIVE;

        // @todo decide what we want to emit
        emit ETHProvisioned(validator.node, validator.pubKey, block.timestamp);

        PufferStrategy strategy = $.strategies[strategyName];

        $.pool.transferETH(address(strategy), _32_ETHER);

        emit SuccesfullyProvisioned(validator.pubKey, index);

        strategy.callStake({ pubKey: validator.pubKey, signature: validator.signature, depositDataRoot: depositDataRoot });
    }

    function skipProvisioning(bytes32 strategyName) external onlyGuardians {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 skippedIndex = $.nextToBeProvisioned[strategyName];
        // Change the status of that validator
        $.validators[strategyName][skippedIndex].status = Status.SKIPPED;

        // Transfer pufETH to that node operator
        $.pool.transfer($.validators[strategyName][skippedIndex].node, $.validators[strategyName][skippedIndex].bond);

        ++$.nextToBeProvisioned[strategyName];
        emit ValidatorSkipped(strategyName, skippedIndex);
    }

    function stopValidator(bytes32 strategyName, uint256 idx) external onlyGuardians {
        // @todo logic for this..

        ProtocolStorage storage $ = _getPufferProtocolStorage();

        Validator storage validator = $.validators[strategyName][idx];
        validator.status = Status.EXITED;

        uint256 pufETHAmount = validator.bond;

        // uint256 ethAmount = $.withdrawalPool.withdrawETH(address(this), pufETHAmount);
    }

    function extendCommitment(bytes32 strategyName, uint256 validatorIndex) external payable {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        Validator storage validator = $.validators[strategyName][validatorIndex];

        uint256 smoothingCommitment = $.smoothingCommitments[strategyName];

        // Node operator can purchase commitment for multiple months
        if ((msg.value % smoothingCommitment) != 0) {
            revert InvalidETHAmount();
        }

        uint256 timePaidInDays = (msg.value / smoothingCommitment) * 30 days;

        validator.commitmentExpiration = uint40(block.timestamp + timePaidInDays);

        emit SmoothingCommitmentPaid(validator.pubKey, block.timestamp, msg.value);

        _transferFunds($);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function stopRegistration(bytes32 strategyName, uint256 validatorIndex) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        // `msg.sender` is the Node Operator
        Validator storage validator = $.validators[strategyName][validatorIndex];

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

    function proofOfReserve(uint256 ethAmount, uint256 lockedETH, uint256 pufETHTotalSupply, uint256 blockNumber)
        external
        restricted
    {
        PufferPoolStorage storage $ = _getPuferPoolStorage();
        //@audit figure out if we want more restrictions on this
        if (block.number < blockNumber) {
            revert InvalidData();
        }

        if (block.number - $.lastUpdate < _UPDATE_INTERVAL) {
            revert OutsideUpdateWindow();
        }
        $.ethAmount = ethAmount;
        $.lockedETH = lockedETH;
        $.pufETHTotalSupply = pufETHTotalSupply;
        $.lastUpdate = blockNumber;

        _resetInterval();

        emit BackingUpdated(ethAmount, lockedETH, pufETHTotalSupply, blockNumber);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function createPufferStrategy(bytes32 strategyName) external restricted returns (address) {
        return _createPufferStrategy(strategyName);
    }

    function setStrategyWeights(bytes32[] calldata newStrategyWeights) external restricted {
        _setStrategyWeights(newStrategyWeights);
    }

    function setValidatorLimitPerInterval(uint256 newLimit) external restricted {
        _setValidatorLimitPerInterval(newLimit);
    }

    function setSmoothingCommitment(bytes32 strategyName, uint256 smoothingCommitment) external restricted {
        _setSmoothingCommitment(strategyName, smoothingCommitment);
    }

    function setProtocolFeeRate(uint256 protocolFeeRate) external restricted {
        _setProtocolFeeRate(protocolFeeRate);
    }

    function getValidatorLimitPerInterval() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return uint256($.validatorLimitPerInterval);
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

    function getValidatorsAddresses(bytes32 strategyName) external view returns (address[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 numOfValidators = $.pendingValidatorIndicies[strategyName];

        address[] memory addresses = new address[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; i++) {
            addresses[i] = $.validators[strategyName][i].node;
        }

        return addresses;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getSmoothingCommitment(bytes32 strategyName) external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.smoothingCommitments[strategyName];
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getNextValidatorToProvision() public view returns (bytes32, uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 strategySelectionIndex = $.strategySelectIndex;
        // Do Weights number of rounds
        uint256 strategyEndIndex = strategySelectionIndex + $.strategyWeights.length;
        uint256 strategyWeightsLength = $.strategyWeights.length;

        // Read from the storage
        bytes32 strategyName = $.strategyWeights[strategySelectionIndex % strategyWeightsLength];

        // Iterate through all strategies to see if there is a validator ready to be provisioned
        while (strategySelectionIndex < strategyEndIndex) {
            // Read the index for that strategyName
            uint256 validatorIndex = $.nextToBeProvisioned[strategyName];

            // Check the next 5 spots for that queue and try to find a validator in a valid state for provisioning
            for (uint256 idx = validatorIndex; idx < validatorIndex + 5; ++idx) {
                // If we find it, return it
                if ($.validators[strategyName][idx].status == Status.PENDING) {
                    return (strategyName, idx);
                }
            }
            // If not, try the next strategy

            ++strategySelectionIndex;
            strategyName = $.strategyWeights[strategySelectionIndex % strategyWeightsLength];
        }

        // No validators found
        return (bytes32("NO_VALIDATORS"), type(uint256).max);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getNextValidatorToBeProvisionedIndex(bytes32 strategyName) external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.nextToBeProvisioned[strategyName];
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getPendingValidatorIndex(bytes32 strategyName) external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.pendingValidatorIndicies[strategyName];
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getValidators(bytes32 strategyName) external view returns (bytes[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 numOfValidators = $.pendingValidatorIndicies[strategyName];

        bytes[] memory validators = new bytes[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; i++) {
            validators[i] = bytes($.validators[strategyName][i].pubKey);
        }

        return validators;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getValidatorInfo(bytes32 strategyName, uint256 validatorIndex) external view returns (Validator memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.validators[strategyName][validatorIndex];
    }

    function getStrategyAddress(bytes32 strategyName) external view returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return address($.strategies[strategyName]);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getWithdrawalPool() external view returns (WithdrawalPool) {
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

    /**
     * @inheritdoc IPufferProtocol
     */
    function getWithdrawalCredentials(address strategy) public view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), IPufferStrategy(strategy).getEigenPod());
    }

    function getPayload(bytes32 strategyName) external view returns (bytes[] memory, bytes memory, uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        bytes[] memory pubKeys = $.guardianModule.getGuardiansEnclavePubkeys();
        bytes memory withdrawalCredentials = getWithdrawalCredentials(address($.strategies[strategyName]));
        uint256 threshold = GUARDIANS.getThreshold();

        return (pubKeys, withdrawalCredentials, threshold);
    }

    function _setSmoothingCommitment(bytes32 strategyName, uint256 smoothingCommitment) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldSmoothingCommitment = $.smoothingCommitments[strategyName];
        $.smoothingCommitments[strategyName] = smoothingCommitment;
        emit CommitmentChanged(strategyName, oldSmoothingCommitment, smoothingCommitment);
    }

    function _transferFunds(ProtocolStorage storage $) internal {
        uint256 amount = msg.value - _VALIDATOR_BOND;

        uint256 treasuryAmount = _sendETH(TREASURY, amount, $.protocolFeeRate);
        uint256 withdrawalPoolAmount = _sendETH(address($.withdrawalPool), amount, $.withdrawalPoolRate);
        uint256 guardiansAmount = _sendETH(address(GUARDIANS), amount, $.guardiansFeeRate);

        uint256 poolAmount = amount - (treasuryAmount + withdrawalPoolAmount + guardiansAmount);
        $.pool.paySmoothingCommitment{ value: poolAmount }();
    }

    function _sendETH(address to, uint256 amount, uint256 rate) internal returns (uint256 toSend) {
        toSend = FixedPointMathLib.fullMulDiv(amount, rate, _ONE_HUNDRED_WAD);

        if (toSend != 0) {
            to.safeTransferETH(toSend);
        }

        emit TransferredETH(to, toSend);

        return toSend;
    }

    function _setStrategyWeights(bytes32[] memory newStrategyWeights) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        bytes32[] memory oldStrategyWeights = $.strategyWeights;
        $.strategyWeights = newStrategyWeights;
        emit StrategyWeightsChanged(oldStrategyWeights, newStrategyWeights);
    }

    function _setProtocolFeeRate(uint256 protocolFee) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldProtocolFee = $.protocolFeeRate;
        $.protocolFeeRate = SafeCastLib.toUint72(protocolFee);
        emit ProtocolFeeRateChanged(oldProtocolFee, protocolFee);
    }

    function _resetInterval() internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        $.numberOfValidatorsRegisteredInThisInterval = 0;
        emit IntervalReset();
    }

    function _createPufferStrategy(bytes32 strategyName) internal returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        PufferStrategy strategy = _createNewPufferStrategy(strategyName);
        $.strategies[strategyName] = strategy;
        emit NewPufferStrategyCreated(address(strategy));
        return address(strategy);
    }

    function _createNewPufferStrategy(bytes32 strategyName) internal returns (PufferStrategy strategy) {
        bytes memory deploymentData = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(PUFFER_STRATEGY_BEACON, abi.encodeCall(PufferStrategy.initialize, (this, strategyName)))
        );

        // solhint-disable-next-line no-inline-assembly
        assembly {
            strategy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), strategyName)
        }

        if (address(strategy) == address(0)) {
            revert Create2Failed();
        }

        return PufferStrategy(payable(address(strategy)));
    }

    function _setValidatorLimitPerInterval(uint256 newLimit) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        $.validatorLimitPerInterval = SafeCastLib.toUint16(newLimit);
        uint256 oldLimit = uint256($.validatorLimitPerInterval);
        emit ValidatorLimitPerIntervalChanged(oldLimit, newLimit);
    }

    function _incrementStrategySelectionCounter(ProtocolStorage storage $, bytes32 strategyName) internal {
        // Increment next validator to be provisioned index
        ++$.nextToBeProvisioned[strategyName];
        // Increment strategy selection index
        ++$.strategySelectIndex;
    }

    function _checkValidatorRegistrationInputs(
        ValidatorKeyData calldata data,
        bytes32 strategyName,
        ProtocolStorage storage $
    ) internal {
        // +1 To check if this registration would go over the limit
        if (($.numberOfValidatorsRegisteredInThisInterval + 1) > $.validatorLimitPerInterval) {
            revert ValidatorLimitPerIntervalReached();
        }

        if (data.blsPubKey.length != _BLS_PUB_KEY_LENGTH) {
            revert InvalidBLSPubKey();
        }

        address strategy = address($.strategies[strategyName]);

        if (strategy == address(0)) {
            revert InvalidPufferStrategy();
        }

        if (data.raveEvidence.length == 0) {
            revert InvalidRaveEvidence();
        }

        uint256 numGuardians = GUARDIANS.getOwners().length;

        if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeyShares.length != numGuardians) {
            revert InvalidBLSPublicKeyShares();
        }

        uint256 smoothingCommitment = $.smoothingCommitments[strategyName];

        if (msg.value != (smoothingCommitment + _VALIDATOR_BOND)) {
            revert InvalidETHAmount();
        }
    }

    function _toLittleEndian64(uint64 value) internal pure returns (bytes memory ret) {
        // Copied https://github.com/ethereum/consensus-specs/blob/b04430332ec190774f4dfc039de6e83afe3327ee/solidity_deposit_contract/deposit_contract.sol#L165
        ret = new bytes(8);
        bytes8 bytesValue = bytes8(value);
        // Byteswapping during copying to bytes.
        ret[0] = bytesValue[7];
        ret[1] = bytesValue[6];
        ret[2] = bytesValue[5];
        ret[3] = bytesValue[4];
        ret[4] = bytesValue[3];
        ret[5] = bytesValue[2];
        ret[6] = bytesValue[1];
        ret[7] = bytesValue[0];
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
