// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Status } from "puffer/struct/Status.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";
import { ProtocolStorage } from "puffer/struct/ProtocolStorage.sol";
import { PufferPoolStorage } from "puffer/struct/PufferPoolStorage.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
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
     * @dev ETH Amount required to be deposited as a bond if the node operator uses SGX
     */
    uint256 internal constant _ENCLAVE_VALIDATOR_BOND = 1 ether;

    /**
     * @dev ETH Amount required to be deposited as a bond if the node operator doesn't use SGX
     */
    uint256 internal constant _NO_ENCLAVE_VALIDATOR_BOND = 2 ether;

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

    constructor(Safe guardians, address payable treasury, address strategyBeacon) payable {
        PUFFER_STRATEGY_BEACON = strategyBeacon;
        TREASURY = treasury;
        GUARDIANS = guardians;
        _disableInitializers();
    }

    function initialize(
        address accessManager,
        IPufferPool pool,
        IWithdrawalPool withdrawalPool,
        address guardianSafeModule,
        address noRestakingStrategy,
        uint256[] calldata smoothingCommitments
    ) external initializer {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        __AccessManaged_init(accessManager);
        $.pool = pool;
        $.withdrawalPool = withdrawalPool;
        $.guardianModule = GuardianModule(guardianSafeModule);
        _setProtocolFeeRate(2 * FixedPointMathLib.WAD); // 2%
        _setWithdrawalPoolRate(10 * FixedPointMathLib.WAD); // 10 %
        _setGuardiansFeeRate(5 * 1e17); // 0.5 %
        _setValidatorLimitPerInterval(20);
        _setSmoothingCommitments(smoothingCommitments);
        bytes32[] memory weights = new bytes32[](1);
        weights[0] = _NO_RESTAKING;
        _setStrategyWeights(weights);
        _changeStrategy(_NO_RESTAKING, IPufferStrategy(noRestakingStrategy));
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function registerValidatorKey(ValidatorKeyData calldata data, bytes32 strategyName, uint256 numberOfMonths)
        external
        payable
    {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 validatorBond = data.raveEvidence.length > 0 ? _ENCLAVE_VALIDATOR_BOND : _NO_ENCLAVE_VALIDATOR_BOND;

        _checkValidatorRegistrationInputs({
            $: $,
            data: data,
            strategyName: strategyName,
            validatorBond: validatorBond,
            numberOfMonths: numberOfMonths
        });

        uint256 pufETHReceived = $.pool.depositETH{ value: validatorBond }();

        // Save the validator data to storage
        Validator memory validator;
        validator.pubKey = data.blsPubKey;
        validator.signature = data.signature;
        validator.status = Status.PENDING;
        validator.strategy = address($.strategies[strategyName]);
        validator.bond = SafeCastLib.toUint64(pufETHReceived);
        validator.monthsCommited = SafeCastLib.toUint40(numberOfMonths);
        validator.commitmentAmount = SafeCastLib.toUint64(msg.value - validatorBond);
        // @todo validator.startDate = block.timestamp;
        validator.node = msg.sender;

        uint256 validatorIndex = $.pendingValidatorIndicies[strategyName];
        $.validators[strategyName][validatorIndex] = validator;

        // Increment indices for this strategy and number of validators registered
        ++$.pendingValidatorIndicies[strategyName];
        ++$.numberOfValidatorsRegisteredInThisInterval;

        emit ValidatorKeyRegistered(data.blsPubKey, validatorIndex);

        _transferFunds($, validatorBond);
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

        IPufferStrategy strategy = $.strategies[strategyName];

        $.pool.transferETH(address(strategy), _32_ETHER);

        emit SuccesfullyProvisioned(validator.pubKey, index);

        strategy.callStake({ pubKey: validator.pubKey, signature: validator.signature, depositDataRoot: depositDataRoot });
    }

    function extendCommitment(bytes32 strategyName, uint256 validatorIndex, uint256 numberOfMonths) external payable {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        Validator storage validator = $.validators[strategyName][validatorIndex];

        if (numberOfMonths > 13) {
            revert InvalidNumberOfMonths();
        }

        uint256 smoothingCommitment = $.smoothingCommitments[numberOfMonths - 1];

        // Node operator can purchase commitment for multiple months
        if ((msg.value != smoothingCommitment)) {
            revert InvalidETHAmount();
        }

        validator.monthsCommited += uint40(numberOfMonths);
        validator.commitmentAmount = uint64(msg.value);

        emit SmoothingCommitmentPaid(validator.pubKey, block.timestamp, msg.value);

        _transferFunds($, 0);
    }

    function collectRewards() external {
        // ProtocolStorage storage $ = _getPufferProtocolStorage();
        //@todo
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

        // If this validator was next in line to be provisioned
        // Increment the counter
        if ($.nextToBeProvisioned[strategyName] == validatorIndex) {
            ++$.nextToBeProvisioned[strategyName];
        }

        $.pool.transfer(validator.node, validator.bond);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function skipProvisioning(bytes32 strategyName) external restricted {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 skippedIndex = $.nextToBeProvisioned[strategyName];
        // Change the status of that validator
        $.validators[strategyName][skippedIndex].status = Status.SKIPPED;

        // Transfer pufETH to that node operator
        // slither-disable-next-line unchecked-transfer
        $.pool.transfer($.validators[strategyName][skippedIndex].node, $.validators[strategyName][skippedIndex].bond);

        ++$.nextToBeProvisioned[strategyName];
        emit ValidatorSkipped(strategyName, skippedIndex);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function changeStrategy(bytes32 strategyName, IPufferStrategy newStrategy) external restricted {
        _changeStrategy(strategyName, newStrategy);
    }

    function stopValidator(bytes32 strategyName, uint256 idx) external restricted {
        // @todo logic for this..

        ProtocolStorage storage $ = _getPufferProtocolStorage();

        Validator storage validator = $.validators[strategyName][idx];
        validator.status = Status.EXITED;

        // uint256 pufETHAmount = validator.bond;

        // uint256 ethAmount = $.withdrawalPool.withdrawETH(address(this), pufETHAmount);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
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

    /**
     * @inheritdoc IPufferProtocol
     */
    function setStrategyWeights(bytes32[] calldata newStrategyWeights) external restricted {
        _setStrategyWeights(newStrategyWeights);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function setValidatorLimitPerInterval(uint256 newLimit) external restricted {
        _setValidatorLimitPerInterval(newLimit);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function setSmoothingCommitments(uint256[] calldata smoothingCommitments) external restricted {
        _setSmoothingCommitments(smoothingCommitments);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function setProtocolFeeRate(uint256 protocolFeeRate) external restricted {
        _setProtocolFeeRate(protocolFeeRate);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function setGuardiansFeeRate(uint256 newRate) external restricted {
        _setGuardiansFeeRate(newRate);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function setWithdrawalPoolRate(uint256 newRate) external restricted {
        _setWithdrawalPoolRate(newRate);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getValidatorLimitPerInterval() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return uint256($.validatorLimitPerInterval);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getValidators(bytes32 strategyName) external view returns (Validator[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 numOfValidators = $.pendingValidatorIndicies[strategyName];

        Validator[] memory validators = new Validator[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; i++) {
            validators[i] = $.validators[strategyName][i];
        }

        return validators;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getSmoothingCommitment(uint256 numberOfMonths) external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.smoothingCommitments[numberOfMonths - 1];
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
    function getWithdrawalPool() external view returns (IWithdrawalPool) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.withdrawalPool;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getGuardianModule() external view returns (IGuardianModule) {
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
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), IPufferStrategy(strategy).getWithdrawalCredentials());
    }

    function getPayload(bytes32 strategyName, bool usingEnclave, uint256 numberOfMonths)
        external
        view
        returns (bytes[] memory, bytes memory, uint256, uint256)
    {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        bytes[] memory pubKeys = $.guardianModule.getGuardiansEnclavePubkeys();
        bytes memory withdrawalCredentials = getWithdrawalCredentials(address($.strategies[strategyName]));
        uint256 threshold = GUARDIANS.getThreshold();
        uint256 validatorBond = usingEnclave ? _ENCLAVE_VALIDATOR_BOND : _NO_ENCLAVE_VALIDATOR_BOND;
        uint256 ethAmount = validatorBond + $.smoothingCommitments[numberOfMonths - 1];

        return (pubKeys, withdrawalCredentials, threshold, ethAmount);
    }

    function _setSmoothingCommitments(uint256[] calldata smoothingCommitments) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256[] memory oldSmoothingCommitments = $.smoothingCommitments;
        $.smoothingCommitments = smoothingCommitments;
        emit CommitmentsChanged(oldSmoothingCommitments, smoothingCommitments);
    }

    function _transferFunds(ProtocolStorage storage $, uint256 bond) internal {
        uint256 amount = msg.value - bond;

        uint256 treasuryAmount = _sendETH(TREASURY, amount, $.protocolFeeRate);
        uint256 withdrawalPoolAmount = _sendETH(address($.withdrawalPool), amount, $.withdrawalPoolRate);
        uint256 guardiansAmount = _sendETH(address(GUARDIANS), amount, $.guardiansFeeRate);

        uint256 poolAmount = amount - (treasuryAmount + withdrawalPoolAmount + guardiansAmount);
        $.pool.paySmoothingCommitment{ value: poolAmount }();
    }

    function _setGuardiansFeeRate(uint256 newRate) internal {
        // @todo decide constraints
        // Revert if the new rate is bigger than 5%
        if (newRate > (5 * FixedPointMathLib.WAD)) {
            revert InvalidData();
        }
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldRate = $.guardiansFeeRate;
        $.guardiansFeeRate = SafeCastLib.toUint72(newRate);
        emit GuardiansFeeRateChanged(oldRate, newRate);
    }

    function _sendETH(address to, uint256 amount, uint256 rate) internal returns (uint256 toSend) {
        toSend = FixedPointMathLib.fullMulDiv(amount, rate, _ONE_HUNDRED_WAD);

        if (toSend != 0) {
            emit TransferredETH(to, toSend);
            to.safeTransferETH(toSend);
        }

        return toSend;
    }

    function _setStrategyWeights(bytes32[] memory newStrategyWeights) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        bytes32[] memory oldStrategyWeights = $.strategyWeights;
        $.strategyWeights = newStrategyWeights;
        emit StrategyWeightsChanged(oldStrategyWeights, newStrategyWeights);
    }

    function _setProtocolFeeRate(uint256 protocolFee) internal {
        // @todo decide constraints
        // Revert if the new rate is bigger than 10%
        if (protocolFee > (10 * FixedPointMathLib.WAD)) {
            revert InvalidData();
        }
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldProtocolFee = $.protocolFeeRate;
        $.protocolFeeRate = SafeCastLib.toUint72(protocolFee);
        emit ProtocolFeeRateChanged(oldProtocolFee, protocolFee);
    }

    function _setWithdrawalPoolRate(uint256 withdrawalPoolRate) internal {
        // @todo decide constraints
        // Revert if the new rate is bigger than 10%
        if (withdrawalPoolRate > (10 * FixedPointMathLib.WAD)) {
            revert InvalidData();
        }
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldWithdrawalPoolRate = $.withdrawalPoolRate;
        $.withdrawalPoolRate = SafeCastLib.toUint64(withdrawalPoolRate);
        emit WithdrawalPoolRateChanged(oldWithdrawalPoolRate, withdrawalPoolRate);
    }

    function _resetInterval() internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        $.numberOfValidatorsRegisteredInThisInterval = 0;
        emit IntervalReset();
    }

    function _createPufferStrategy(bytes32 strategyName) internal returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        if (address($.strategies[strategyName]) != address(0)) {
            revert StrategyAlreadyExists();
        }
        IPufferStrategy strategy = _createNewPufferStrategy(strategyName);
        $.strategies[strategyName] = strategy;
        emit NewPufferStrategyCreated(address(strategy));
        return address(strategy);
    }

    function _createNewPufferStrategy(bytes32 strategyName) internal returns (IPufferStrategy strategy) {
        bytes memory deploymentData = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(
                PUFFER_STRATEGY_BEACON,
                abi.encodeWithSignature("initialize(address,bytes32,address)", this, strategyName, authority())
            )
        );

        // solhint-disable-next-line no-inline-assembly
        assembly {
            strategy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), strategyName)
        }

        if (address(strategy) == address(0)) {
            revert Create2Failed();
        }

        return IPufferStrategy(payable(address(strategy)));
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
        ProtocolStorage storage $,
        ValidatorKeyData calldata data,
        bytes32 strategyName,
        uint256 validatorBond,
        uint256 numberOfMonths
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

        uint256 numGuardians = GUARDIANS.getOwners().length;

        if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeySet.length != (GUARDIANS.getThreshold() * _BLS_PUB_KEY_LENGTH)) {
            revert InvalidBLSPublicKeySet();
        }

        uint256 smoothingCommitment = $.smoothingCommitments[numberOfMonths - 1];

        if (msg.value != (smoothingCommitment + validatorBond)) {
            revert InvalidETHAmount();
        }
    }

    function _changeStrategy(bytes32 strategyName, IPufferStrategy newStrategy) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        IPufferStrategy oldStrategy = $.strategies[strategyName];
        if (address(oldStrategy) != address(0)) {
            revert InvalidPufferStrategy();
        }
        $.strategies[strategyName] = newStrategy;
        emit StrategyChanged(strategyName, address(oldStrategy), address(newStrategy));
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
