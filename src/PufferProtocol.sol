// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IPufferModuleFactory } from "puffer/interface/IPufferModuleFactory.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Status } from "puffer/struct/Status.sol";
import { ProtocolStorage } from "puffer/struct/ProtocolStorage.sol";
import { PufferPoolStorage } from "puffer/struct/PufferPoolStorage.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { LibBeaconchainContract } from "puffer/LibBeaconchainContract.sol";
import { MerkleProof } from "openzeppelin/utils/cryptography/MerkleProof.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { SafeCastLib } from "solady/utils/SafeCastLib.sol";

/**
 * @title PufferProtocol
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferProtocol is IPufferProtocol, AccessManagedUpgradeable, UUPSUpgradeable, PufferProtocolStorage {
    using SafeTransferLib for address;
    using SafeTransferLib for address payable;

    /**
     * @dev Burst threshold
     */
    uint256 internal constant _BURST_THRESHOLD = 22;

    /**
     * @dev BLS public keys are 48 bytes long
     */
    uint256 internal constant _BLS_PUB_KEY_LENGTH = 48;

    /**
     * @dev ETH Amount required to be deposited as a bond if the node operator uses SGX
     */
    uint256 internal constant _ENCLAVE_VALIDATOR_BOND = 1 ether;

    /**
     * @dev ETH Amount required to be deposited as a bond if the node operator doesn't use SGX
     */
    uint256 internal constant _NO_ENCLAVE_VALIDATOR_BOND = 2 ether;

    /**
     * @dev Default "NO_RESTAKING" module
     */
    bytes32 internal constant _NO_RESTAKING = bytes32("NO_RESTAKING");

    /**
     * @dev Number of blocks
     * 7141 * 12(avg block time) = 85692 seconds
     * 85692 seconds ~ 23.8 hours
     */
    uint256 internal constant _UPDATE_INTERVAL = 7141;

    /**
     * @dev Puffer Finance treasury
     */
    address payable public immutable TREASURY;

    /**
     * @inheritdoc IPufferProtocol
     */
    IGuardianModule public immutable override GUARDIAN_MODULE;

    /**
     * @inheritdoc IPufferProtocol
     */
    IPufferPool public immutable override POOL;

    /**
     * @inheritdoc IPufferProtocol
     */
    IWithdrawalPool public immutable override WITHDRAWAL_POOL;

    // /**
    //  * @inheritdoc IPufferProtocol
    //  */
    IPufferModuleFactory public immutable PUFFER_MODULE_FACTORY;

    constructor(
        IWithdrawalPool withdrawalPool,
        IPufferPool pool,
        IGuardianModule guardianModule,
        address payable treasury,
        address moduleFactory
    ) payable {
        TREASURY = treasury;
        GUARDIAN_MODULE = guardianModule;
        POOL = pool;
        WITHDRAWAL_POOL = withdrawalPool;
        PUFFER_MODULE_FACTORY = IPufferModuleFactory(moduleFactory);
        _disableInitializers();
    }

    function initialize(address accessManager, address noRestakingModule, uint256[] calldata smoothingCommitments)
        external
        initializer
    {
        __AccessManaged_init(accessManager);
        _setProtocolFeeRate(2 * FixedPointMathLib.WAD); // 2%
        _setWithdrawalPoolRate(10 * FixedPointMathLib.WAD); // 10 %
        _setGuardiansFeeRate(5 * 1e17); // 0.5 %
        _setValidatorLimitPerInterval(20);
        _setSmoothingCommitments(smoothingCommitments);
        bytes32[] memory weights = new bytes32[](1);
        weights[0] = _NO_RESTAKING;
        _setModuleWeights(weights);
        _changeModule(_NO_RESTAKING, IPufferModule(noRestakingModule));
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        $.numberOfActiveValidators = 10000;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function registerValidatorKey(ValidatorKeyData calldata data, bytes32 moduleName, uint256 numberOfMonths)
        external
        payable
        restricted
    {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 validatorBond = data.raveEvidence.length > 0 ? _ENCLAVE_VALIDATOR_BOND : _NO_ENCLAVE_VALIDATOR_BOND;

        _checkValidatorRegistrationInputs({
            $: $,
            data: data,
            moduleName: moduleName,
            validatorBond: validatorBond,
            numberOfMonths: numberOfMonths
        });

        // slither-disable-next-line arbitrary-send-eth
        uint256 pufETHReceived = POOL.depositETH{ value: validatorBond }();

        // Save the validator data to storage
        Validator memory validator;
        validator.pubKey = data.blsPubKey;
        validator.signature = data.signature;
        validator.status = Status.PENDING;
        validator.module = address($.modules[moduleName]);
        // No need for Safecast because of the validations inside of _checkValidatorRegistrationInputs
        validator.bond = uint64(pufETHReceived);
        validator.monthsCommitted = uint40(numberOfMonths);
        validator.lastCommitmentPayment = uint64(block.timestamp);
        validator.node = msg.sender;

        uint256 validatorIndex = $.pendingValidatorIndicies[moduleName];
        $.validators[moduleName][validatorIndex] = validator;

        // Increment indices for this module and number of validators registered
        unchecked {
            ++$.pendingValidatorIndicies[moduleName];
            ++$.numberOfValidatorsRegisteredInThisInterval;
            ++$.activePufferValidators;
        }

        emit ValidatorKeyRegistered(data.blsPubKey, validatorIndex, moduleName, (data.raveEvidence.length > 0));

        _transferFunds($, validatorBond);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getDepositDataRoot(bytes calldata pubKey, bytes calldata signature, bytes calldata withdrawalCredentials)
        external
        pure
        returns (bytes32)
    {
        return LibBeaconchainContract.getDepositDataRoot(pubKey, signature, withdrawalCredentials);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function provisionNode(bytes[] calldata guardianEnclaveSignatures) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        (bytes32 moduleName, uint256 index) = getNextValidatorToProvision();

        Validator memory validator = $.validators[moduleName][index];

        // Increment next validator to be provisioned index
        $.nextToBeProvisioned[moduleName] = index + 1;
        unchecked {
            // Increment module selection index
            ++$.moduleSelectIndex;
        }

        bytes memory withdrawalCredentials = getWithdrawalCredentials(validator.module);

        bytes32 depositDataRoot = this.getDepositDataRoot({
            pubKey: validator.pubKey,
            signature: validator.signature,
            withdrawalCredentials: withdrawalCredentials
        });

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateProvisionNode({
            pubKey: validator.pubKey,
            signature: validator.signature,
            depositDataRoot: depositDataRoot,
            withdrawalCredentials: withdrawalCredentials,
            guardianEnclaveSignatures: guardianEnclaveSignatures
        });

        $.validators[moduleName][index].status = Status.ACTIVE;

        IPufferModule module = $.modules[moduleName];

        // Transfer 32 ETH to the module
        POOL.transferETH(address(module), 32 ether);

        emit SuccesfullyProvisioned(validator.pubKey, index, moduleName);

        module.callStake({ pubKey: validator.pubKey, signature: validator.signature, depositDataRoot: depositDataRoot });
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function extendCommitment(bytes32 moduleName, uint256 validatorIndex, uint256 numberOfMonths) external payable {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        Validator storage validator = $.validators[moduleName][validatorIndex];

        // Causes panic for invalid numberOfMonths
        uint256 smoothingCommitment = $.smoothingCommitments[numberOfMonths - 1];

        // Node operator can purchase commitment for multiple months
        if ((msg.value != smoothingCommitment)) {
            revert InvalidETHAmount();
        }

        // No need for Safecast because of the validations above
        validator.monthsCommitted = uint40(numberOfMonths);
        validator.lastCommitmentPayment = uint64(block.timestamp);

        emit SmoothingCommitmentPaid(validator.pubKey, block.timestamp, msg.value);

        _transferFunds($, 0);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function stopRegistration(bytes32 moduleName, uint256 validatorIndex) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        // `msg.sender` is the Node Operator
        Validator storage validator = $.validators[moduleName][validatorIndex];

        if (validator.status != Status.PENDING) {
            revert InvalidValidatorState(validator.status);
        }

        if (msg.sender != validator.node) {
            revert Unauthorized();
        }

        // Update the status to DEQUEUED
        validator.status = Status.DEQUEUED;

        emit ValidatorDequeued(validator.pubKey, validatorIndex);

        // If this validator was next in line to be provisioned
        // Increment the counter
        if ($.nextToBeProvisioned[moduleName] == validatorIndex) {
            unchecked {
                ++$.nextToBeProvisioned[moduleName];
            }
        }

        // slither-disable-next-line unchecked-transfer
        POOL.transfer(validator.node, validator.bond);
    }

    /**
     * @notice Submit a valid MerkleProof and get back the Bond deposited if the validator was not slashed
     * @dev Anybody can trigger a validator exit as long as the proofs submitted are valid
     */
    function stopValidator(
        bytes32 moduleName,
        uint256 validatorIndex,
        uint256 blockNumber,
        uint256 withdrawalAmount,
        bool wasSlashed,
        bytes32[] calldata merkleProof
    ) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        Validator storage validator = $.validators[moduleName][validatorIndex];

        if (validator.status != Status.ACTIVE) {
            revert InvalidValidatorState(validator.status);
        }

        bytes32 leaf =
            keccak256(bytes.concat(keccak256(abi.encode(moduleName, validatorIndex, withdrawalAmount, wasSlashed))));

        bytes32 withdrawalRoot = $.fullWithdrawalsRoots[blockNumber];

        if (!MerkleProof.verifyCalldata(merkleProof, withdrawalRoot, leaf)) {
            revert InvalidMerkleProof();
        }
        // Store what we need
        uint256 validatorBond = validator.bond;
        address node = validator.node;
        bytes memory pubKey = validator.pubKey;

        // Remove what we don't
        delete validator.module;
        delete validator.node;
        delete validator.monthsCommitted;
        delete validator.bond;
        delete validator.pubKey;
        delete validator.signature;
        validator.status = Status.EXITED;
        $.activePufferValidators -= 1;

        // Burn everything if the validator was slashed
        if (wasSlashed) {
            POOL.burn(validatorBond);
        } else {
            // slither-disable-next-line unchecked-transfer
            POOL.transfer(node, validatorBond);
        }

        emit ValidatorExited(pubKey, validatorIndex, moduleName);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function skipProvisioning(bytes32 moduleName, bytes[] calldata guardianEOASignatures) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 skippedIndex = $.nextToBeProvisioned[moduleName];

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateSkipProvisioning({
            moduleName: moduleName,
            skippedIndex: skippedIndex,
            guardianEOASignatures: guardianEOASignatures
        });

        // Change the status of that validator
        $.validators[moduleName][skippedIndex].status = Status.SKIPPED;

        // Transfer pufETH to that node operator
        // slither-disable-next-line unchecked-transfer
        POOL.transfer($.validators[moduleName][skippedIndex].node, $.validators[moduleName][skippedIndex].bond);

        unchecked {
            ++$.nextToBeProvisioned[moduleName];
        }
        emit ValidatorSkipped($.validators[moduleName][skippedIndex].pubKey, skippedIndex, moduleName);
    }

    /**
     * @notice Posts the full withdrawals root
     * @param root is the Merkle Root hash
     * @param blockNumber is the block number of a withdrawal root
     * @param modules is the array from which modules we are redestributing ETH
     * @param amounts is the array of ETH amounts to pull from modules
     */
    function postFullWithdrawalsRoot(
        bytes32 root,
        uint256 blockNumber,
        address[] calldata modules,
        uint256[] calldata amounts,
        bytes[] calldata guardianSignatures
    ) external {
        if (modules.length != amounts.length) {
            revert InvalidData();
        }
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validatePostFullWithdrawalsRoot({
            root: root,
            blockNumber: blockNumber,
            modules: modules,
            amounts: amounts,
            guardianSignatures: guardianSignatures
        });

        $.fullWithdrawalsRoots[blockNumber] = root;

        // Allocate ETH capital back to the pool ASAP to fuel pool growth
        for (uint256 i = 0; i < modules.length; ++i) {
            uint256 withdrawalPoolAmount =
                FixedPointMathLib.fullMulDiv(amounts[i], $.withdrawalPoolRate, _ONE_HUNDRED_WAD);
            uint256 pufferPoolAmount = amounts[i] - withdrawalPoolAmount;

            // slither-disable-next-line calls-loop
            (bool success,) = IPufferModule(modules[i]).call(address(WITHDRAWAL_POOL), withdrawalPoolAmount, "");
            if (!success) {
                revert Failed();
            }
            // slither-disable-next-line calls-loop
            (success,) = IPufferModule(modules[i]).call(address(POOL), pufferPoolAmount, "");
            if (!success) {
                revert Failed();
            }
        }

        emit FullWithdrawalsRootPosted(blockNumber, root);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function changeModule(bytes32 moduleName, IPufferModule newModule) external restricted {
        _changeModule(moduleName, newModule);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function proofOfReserve(
        uint256 ethAmount,
        uint256 lockedETH,
        uint256 pufETHTotalSupply,
        uint256 blockNumber,
        uint256 numberOfActiveValidators,
        bytes[] calldata guardianSignatures
    ) external {
        PufferPoolStorage storage $ = _getPuferPoolStorage();

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateProofOfReserve({
            ethAmount: ethAmount,
            lockedETH: lockedETH,
            pufETHTotalSupply: pufETHTotalSupply,
            blockNumber: blockNumber,
            numberOfActiveValidators: numberOfActiveValidators,
            guardianSignatures: guardianSignatures
        });

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

        ProtocolStorage storage protocolStorage = _getPufferProtocolStorage();
        // gas optimization to skip zero value
        protocolStorage.numberOfValidatorsRegisteredInThisInterval = 1;
        protocolStorage.numberOfActiveValidators = uint128(numberOfActiveValidators);

        emit BackingUpdated(ethAmount, lockedETH, pufETHTotalSupply, blockNumber);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function createPufferModule(bytes32 moduleName) external restricted returns (address) {
        return _createPufferModule(moduleName);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function setModuleWeights(bytes32[] calldata newModuleWeights) external restricted {
        _setModuleWeights(newModuleWeights);
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
    function getValidators(bytes32 moduleName) external view returns (Validator[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 numOfValidators = $.pendingValidatorIndicies[moduleName];

        Validator[] memory validators = new Validator[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; ++i) {
            validators[i] = $.validators[moduleName][i];
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

        uint256 moduleSelectionIndex = $.moduleSelectIndex;
        // Do Weights number of rounds
        uint256 moduleEndIndex = moduleSelectionIndex + $.moduleWeights.length;
        uint256 moduleWeightsLength = $.moduleWeights.length;

        // Read from the storage
        bytes32 moduleName = $.moduleWeights[moduleSelectionIndex % moduleWeightsLength];

        // Iterate through all modules to see if there is a validator ready to be provisioned
        while (moduleSelectionIndex < moduleEndIndex) {
            // Read the index for that moduleName
            uint256 validatorIndex = $.nextToBeProvisioned[moduleName];

            // Check the next 5 spots for that queue and try to find a validator in a valid state for provisioning
            for (uint256 idx = validatorIndex; idx < validatorIndex + 5; ++idx) {
                // If we find it, return it
                if ($.validators[moduleName][idx].status == Status.PENDING) {
                    return (moduleName, idx);
                }
            }
            unchecked {
                // If not, try the next module
                ++moduleSelectionIndex;
            }
            moduleName = $.moduleWeights[moduleSelectionIndex % moduleWeightsLength];
        }

        // No validators found
        return (bytes32("NO_VALIDATORS"), type(uint256).max);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getNextValidatorToBeProvisionedIndex(bytes32 moduleName) external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.nextToBeProvisioned[moduleName];
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getPendingValidatorIndex(bytes32 moduleName) external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.pendingValidatorIndicies[moduleName];
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getValidatorInfo(bytes32 moduleName, uint256 validatorIndex) external view returns (Validator memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.validators[moduleName][validatorIndex];
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getModuleAddress(bytes32 moduleName) external view returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return address($.modules[moduleName]);
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
    function getWithdrawalCredentials(address module) public view returns (bytes memory) {
        return IPufferModule(module).getWithdrawalCredentials();
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getModuleWeights() external view returns (bytes32[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.moduleWeights;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getModuleSelectIndex() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.moduleSelectIndex;
    }

    /**
     * @notice Returns necessary information to make Guardian's life easier
     */
    function getPayload(bytes32 moduleName, bool usingEnclave, uint256 numberOfMonths)
        external
        view
        returns (bytes[] memory, bytes memory, uint256, uint256)
    {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        bytes[] memory pubKeys = GUARDIAN_MODULE.getGuardiansEnclavePubkeys();
        bytes memory withdrawalCredentials = getWithdrawalCredentials(address($.modules[moduleName]));
        uint256 threshold = GUARDIAN_MODULE.getThreshold();
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

        // If we are above burst threshold, take everything to the treasury
        if (($.activePufferValidators * 100 / $.numberOfActiveValidators) > _BURST_THRESHOLD) {
            _sendETH(TREASURY, amount, _ONE_HUNDRED_WAD);
            return;
        }

        uint256 treasuryAmount = _sendETH(TREASURY, amount, $.protocolFeeRate);
        uint256 withdrawalPoolAmount = _sendETH(address(WITHDRAWAL_POOL), amount, $.withdrawalPoolRate);
        uint256 guardiansAmount = _sendETH(address(GUARDIAN_MODULE), amount, $.guardiansFeeRate);

        uint256 poolAmount = amount - (treasuryAmount + withdrawalPoolAmount + guardiansAmount);
        address(POOL).safeTransferETH(poolAmount);
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

    // _sendETH is sending ETH to trusted addresses (no reentrancy)
    function _sendETH(address to, uint256 amount, uint256 rate) internal returns (uint256 toSend) {
        toSend = FixedPointMathLib.fullMulDiv(amount, rate, _ONE_HUNDRED_WAD);

        if (toSend != 0) {
            emit TransferredETH(to, toSend);
            to.safeTransferETH(toSend);
        }

        return toSend;
    }

    function _setModuleWeights(bytes32[] memory newModuleWeights) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        bytes32[] memory oldModuleWeights = $.moduleWeights;
        $.moduleWeights = newModuleWeights;
        emit ModuleWeightsChanged(oldModuleWeights, newModuleWeights);
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

    function _createPufferModule(bytes32 moduleName) internal returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        if (address($.modules[moduleName]) != address(0)) {
            revert ModuleAlreadyExists();
        }
        IPufferModule module = PUFFER_MODULE_FACTORY.createNewPufferModule(moduleName);
        $.modules[moduleName] = module;
        emit NewPufferModuleCreated(address(module));
        return address(module);
    }

    function _setValidatorLimitPerInterval(uint256 newLimit) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        $.validatorLimitPerInterval = SafeCastLib.toUint16(newLimit);
        uint256 oldLimit = uint256($.validatorLimitPerInterval);
        emit ValidatorLimitPerIntervalChanged(oldLimit, newLimit);
    }

    function _checkValidatorRegistrationInputs(
        ProtocolStorage storage $,
        ValidatorKeyData calldata data,
        bytes32 moduleName,
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

        address module = address($.modules[moduleName]);

        if (module == address(0)) {
            revert InvalidPufferModule();
        }

        uint256 numGuardians = GUARDIAN_MODULE.getGuardians().length;

        if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeySet.length != (GUARDIAN_MODULE.getThreshold() * _BLS_PUB_KEY_LENGTH)) {
            revert InvalidBLSPublicKeySet();
        }

        // panic for invalid `numberOfMonths`
        uint256 smoothingCommitment = $.smoothingCommitments[numberOfMonths - 1];

        if (msg.value != (smoothingCommitment + validatorBond)) {
            revert InvalidETHAmount();
        }
    }

    function _changeModule(bytes32 moduleName, IPufferModule newModule) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        IPufferModule oldModule = $.modules[moduleName];
        if (address(oldModule) != address(0)) {
            revert InvalidPufferModule();
        }
        $.modules[moduleName] = newModule;
        emit ModuleChanged(moduleName, address(oldModule), address(newModule));
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
