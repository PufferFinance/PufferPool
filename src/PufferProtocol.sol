// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";
import { IPufferModuleManager } from "puffer/interface/IPufferModuleManager.sol";
import { IPufferOracleV2 } from "pufETH/interface/IPufferOracleV2.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IBeaconDepositContract } from "puffer/interface/IBeaconDepositContract.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Permit } from "pufETH/structs/Permit.sol";
import { Status } from "puffer/struct/Status.sol";
import { ProtocolStorage, NodeInfo, ModuleLimit } from "puffer/struct/ProtocolStorage.sol";
import { LibBeaconchainContract } from "puffer/LibBeaconchainContract.sol";
import { IERC20Permit } from "openzeppelin/token/ERC20/extensions/IERC20Permit.sol";
import { SafeCast } from "openzeppelin/utils/math/SafeCast.sol";
import { PufferVaultV2 } from "pufETH/PufferVaultV2.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { InvalidAddress } from "puffer/Errors.sol";
import { StoppedValidatorInfo } from "puffer/struct/StoppedValidatorInfo.sol";

/**
 * @title PufferProtocol
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 * @dev Upgradeable smart contract for the Puffer Protocol
 * Storage variables are located in PufferProtocolStorage.sol
 */
contract PufferProtocol is IPufferProtocol, AccessManagedUpgradeable, UUPSUpgradeable, PufferProtocolStorage {
    /**
     * @dev Helper struct for the full withdrawals accounting
     * The amounts of VT and pufETH to burn at the end of the withdrawal
     */
    struct BurnAmounts {
        uint256 vt;
        uint256 pufETH;
    }

    /**
     * @dev Helper struct for the full withdrawals accounting
     * The amounts of pufETH to send to the node operator
     */
    struct Withdrawals {
        uint256 pufETHAmount;
        address node;
    }

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
     * @dev Default "PUFFER_MODULE_0" module
     */
    bytes32 internal constant _PUFFER_MODULE_0 = bytes32("PUFFER_MODULE_0");

    /**
     * @inheritdoc IPufferProtocol
     */
    IGuardianModule public immutable override GUARDIAN_MODULE;

    /**
     * @inheritdoc IPufferProtocol
     */
    ValidatorTicket public immutable override VALIDATOR_TICKET;

    /**
     * @inheritdoc IPufferProtocol
     */
    PufferVaultV2 public immutable override PUFFER_VAULT;

    /**
     * @inheritdoc IPufferProtocol
     */
    IPufferModuleManager public immutable override PUFFER_MODULE_MANAGER;

    /**
     * @inheritdoc IPufferProtocol
     */
    IPufferOracleV2 public immutable override PUFFER_ORACLE;

    /**
     * @inheritdoc IPufferProtocol
     */
    IBeaconDepositContract public immutable override BEACON_DEPOSIT_CONTRACT;

    constructor(
        PufferVaultV2 pufferVault,
        IGuardianModule guardianModule,
        address moduleManager,
        ValidatorTicket validatorTicket,
        IPufferOracleV2 oracle,
        address beaconDepositContract
    ) {
        GUARDIAN_MODULE = guardianModule;
        PUFFER_VAULT = PufferVaultV2(payable(address(pufferVault)));
        PUFFER_MODULE_MANAGER = IPufferModuleManager(moduleManager);
        VALIDATOR_TICKET = validatorTicket;
        PUFFER_ORACLE = oracle;
        BEACON_DEPOSIT_CONTRACT = IBeaconDepositContract(beaconDepositContract);
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract
     */
    function initialize(address accessManager) external initializer {
        if (address(accessManager) == address(0)) {
            revert InvalidAddress();
        }
        __AccessManaged_init(accessManager);
        _createPufferModule(_PUFFER_MODULE_0);
        _setValidatorLimitPerModule(_PUFFER_MODULE_0, type(uint128).max);
        bytes32[] memory weights = new bytes32[](1);
        weights[0] = _PUFFER_MODULE_0;
        _setModuleWeights(weights);
        _changeMinimumVTAmount(28 ether); // 28 Validator Tickets
        _setVTPenalty(10 ether); // 10 Validator Tickets
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function depositValidatorTickets(Permit calldata permit, address node) external restricted {
        if (node == address(0)) {
            revert InvalidAddress();
        }
        // owner: msg.sender is intentional
        // We only want the owner of the Permit signature to be able to deposit using the signature
        // For an invalid signature, the permit will revert, but it is wrapped in try/catch, meaning the transaction execution
        // will continue. If the `msg.sender` did a `VALIDATOR_TICKET.approve(spender, amount)` before calling this
        // And the spender is `msg.sender` the Permit call will revert, but the overall transaction will succeed
        try IERC20Permit(address(VALIDATOR_TICKET)).permit({
            owner: msg.sender,
            spender: address(this),
            value: permit.amount,
            deadline: permit.deadline,
            v: permit.v,
            s: permit.s,
            r: permit.r
        }) { } catch { }

        // slither-disable-next-line unchecked-transfer
        VALIDATOR_TICKET.transferFrom(msg.sender, address(this), permit.amount);

        ProtocolStorage storage $ = _getPufferProtocolStorage();
        $.nodeOperatorInfo[node].vtBalance += SafeCast.toUint96(permit.amount);
        emit ValidatorTicketsDeposited(node, msg.sender, permit.amount);
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function withdrawValidatorTickets(uint96 amount, address recipient) external restricted {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        // Node operator can only withdraw if they have no active or pending validators
        // In the future, we plan to allow node operators to withdraw VTs even if they have active/pending validators.
        if (
            $.nodeOperatorInfo[msg.sender].activeValidatorCount + $.nodeOperatorInfo[msg.sender].pendingValidatorCount
                != 0
        ) {
            revert ActiveOrPendingValidatorsExist();
        }

        // Reverts if insufficient balance
        $.nodeOperatorInfo[msg.sender].vtBalance -= amount;

        // slither-disable-next-line unchecked-transfer
        VALIDATOR_TICKET.transfer(recipient, amount);

        emit ValidatorTicketsWithdrawn(msg.sender, recipient, amount);
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function registerValidatorKey(
        ValidatorKeyData calldata data,
        bytes32 moduleName,
        Permit calldata pufETHPermit,
        Permit calldata vtPermit
    ) external payable restricted {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        // Revert if the permit amounts are non zero, but the msg.value is also non zero
        if (vtPermit.amount != 0 && pufETHPermit.amount != 0 && msg.value > 0) {
            revert InvalidETHAmount();
        }

        _checkValidatorRegistrationInputs({ $: $, data: data, moduleName: moduleName });

        uint256 validatorBond = data.raveEvidence.length > 0 ? _ENCLAVE_VALIDATOR_BOND : _NO_ENCLAVE_VALIDATOR_BOND;
        uint256 bondAmount = PUFFER_VAULT.convertToShares(validatorBond);
        uint256 vtPayment = pufETHPermit.amount == 0 ? msg.value - validatorBond : msg.value;

        uint256 receivedVtAmount;
        // If the VT permit amount is zero, that means that the user is paying for VT with ETH
        if (vtPermit.amount == 0) {
            receivedVtAmount = VALIDATOR_TICKET.purchaseValidatorTicket{ value: vtPayment }(address(this));
        } else {
            _callPermit(address(VALIDATOR_TICKET), vtPermit);
            receivedVtAmount = vtPermit.amount;

            // slither-disable-next-line unchecked-transfer
            VALIDATOR_TICKET.transferFrom(msg.sender, address(this), receivedVtAmount);
        }

        if (receivedVtAmount < $.minimumVtAmount) {
            revert InvalidVTAmount();
        }

        // If the pufETH permit amount is zero, that means that the user is paying the bond with ETH
        if (pufETHPermit.amount == 0) {
            // Mint pufETH and store the bond amount
            bondAmount = PUFFER_VAULT.depositETH{ value: validatorBond }(address(this));
        } else {
            _callPermit(address(PUFFER_VAULT), pufETHPermit);

            // slither-disable-next-line unchecked-transfer
            PUFFER_VAULT.transferFrom(msg.sender, address(this), bondAmount);
        }

        _storeValidatorInformation({
            $: $,
            data: data,
            pufETHAmount: bondAmount,
            moduleName: moduleName,
            vtAmount: receivedVtAmount
        });
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted to Puffer Paymaster
     */
    function provisionNode(
        bytes[] calldata guardianEnclaveSignatures,
        bytes calldata validatorSignature,
        bytes32 depositRootHash
    ) external restricted {
        // We only use depositRootHash in the no enclave case.
        // For enclave case, we don't need to check the depositRootHash
        if (depositRootHash != bytes32(0) && depositRootHash != BEACON_DEPOSIT_CONTRACT.get_deposit_root()) {
            revert InvalidDepositRootHash();
        }

        ProtocolStorage storage $ = _getPufferProtocolStorage();

        (bytes32 moduleName, uint256 index) = getNextValidatorToProvision();

        // Increment next validator to be provisioned index, panics if there is no validator for provisioning
        $.nextToBeProvisioned[moduleName] = index + 1;
        unchecked {
            // Increment module selection index
            ++$.moduleSelectIndex;
        }

        _validateSignaturesAndProvisionValidator({
            $: $,
            moduleName: moduleName,
            index: index,
            guardianEnclaveSignatures: guardianEnclaveSignatures,
            validatorSignature: validatorSignature
        });

        // Update Node Operator info
        address node = $.validators[moduleName][index].node;
        --$.nodeOperatorInfo[node].pendingValidatorCount;
        ++$.nodeOperatorInfo[node].activeValidatorCount;

        // Mark the validator as active
        $.validators[moduleName][index].status = Status.ACTIVE;
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted to Puffer Paymaster
     */
    function batchHandleWithdrawals(
        StoppedValidatorInfo[] calldata validatorInfos,
        bytes[] calldata guardianEOASignatures
    ) external restricted {
        GUARDIAN_MODULE.validateBatchWithdrawals(validatorInfos, guardianEOASignatures);

        ProtocolStorage storage $ = _getPufferProtocolStorage();

        BurnAmounts memory burnAmounts;
        Withdrawals[] memory bondWithdrawals = new Withdrawals[](validatorInfos.length);

        // We MUST NOT do the burning/oracle update/transferring ETH from the PufferModule -> PufferVault
        // because it affects pufETH exchange rate

        // First, we do the calculations
        // slither-disable-start calls-loop
        for (uint256 i = 0; i < validatorInfos.length; ++i) {
            Validator storage validator =
                $.validators[validatorInfos[i].moduleName][validatorInfos[i].pufferModuleIndex];

            if (validator.status != Status.ACTIVE) {
                revert InvalidValidatorState(validator.status);
            }

            // Save the Node address for the bond transfer
            bondWithdrawals[i].node = validator.node;

            // Get the burnAmount for the withdrawal at the current exchange rate
            uint256 burnAmount =
                _getBondBurnAmount({ validatorInfo: validatorInfos[i], validatorBondAmount: validator.bond });
            uint256 vtBurnAmount = _getVTBurnAmount(validatorInfos[i]);
            // Update the burnAmounts
            burnAmounts.pufETH += burnAmount;
            burnAmounts.vt += vtBurnAmount;

            // Store the withdrawal amount for that node operator
            bondWithdrawals[i].pufETHAmount = (validator.bond - burnAmount);

            emit ValidatorExited({
                pubKey: validator.pubKey,
                pufferModuleIndex: validatorInfos[i].pufferModuleIndex,
                moduleName: validatorInfos[i].moduleName,
                pufETHBurnAmount: burnAmount,
                vtBurnAmount: vtBurnAmount
            });

            // Decrease the number of registered validators for that module
            _decreaseNumberOfRegisteredValidators($, validatorInfos[i].moduleName);
            // Storage VT and the active validator count update for the Node Operator
            $.nodeOperatorInfo[validator.node].vtBalance -= SafeCast.toUint96(vtBurnAmount);
            --$.nodeOperatorInfo[validator.node].activeValidatorCount;

            delete validator.node;
            delete validator.bond;
            delete validator.module;
            delete validator.status;
            delete validator.pubKey;
        }

        VALIDATOR_TICKET.burn(burnAmounts.vt);
        // Because we've calculated everything in the previous loop, we can do the burning
        PUFFER_VAULT.burn(burnAmounts.pufETH);
        // Deduct 32 ETH from the `lockedETHAmount` on the PufferOracle
        PUFFER_ORACLE.exitValidators(validatorInfos.length);

        // In this loop, we transfer back the bonds, and do the accounting that affects the exchange rate
        for (uint256 i = 0; i < validatorInfos.length; ++i) {
            // If the withdrawal amount is bigger than 32 ETH, we cap it to 32 ETH
            // The excess is the rewards amount for that Node Operator
            uint256 transferAmount =
                validatorInfos[i].withdrawalAmount > 32 ether ? 32 ether : validatorInfos[i].withdrawalAmount;
            (bool success,) = IPufferModule(validatorInfos[i].module).call(address(PUFFER_VAULT), transferAmount, "");
            if (!success) {
                revert Failed();
            }

            // Skip the empty transfer (validator got slashed)
            if (bondWithdrawals[i].pufETHAmount == 0) {
                continue;
            }
            // slither-disable-next-line unchecked-transfer
            PUFFER_VAULT.transfer(bondWithdrawals[i].node, bondWithdrawals[i].pufETHAmount);
        }
        // slither-disable-start calls-loop
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted to Puffer Paymaster
     */
    function skipProvisioning(bytes32 moduleName, bytes[] calldata guardianEOASignatures) external restricted {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 skippedIndex = $.nextToBeProvisioned[moduleName];

        address node = $.validators[moduleName][skippedIndex].node;

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateSkipProvisioning({
            moduleName: moduleName,
            skippedIndex: skippedIndex,
            guardianEOASignatures: guardianEOASignatures
        });

        // Burn VT penalty amount from the Node Operator
        VALIDATOR_TICKET.burn($.vtPenalty);
        $.nodeOperatorInfo[node].vtBalance -= SafeCast.toUint96($.vtPenalty);
        --$.nodeOperatorInfo[node].pendingValidatorCount;

        // Change the status of that validator
        $.validators[moduleName][skippedIndex].status = Status.SKIPPED;

        // Transfer pufETH to that node operator
        // slither-disable-next-line unchecked-transfer
        PUFFER_VAULT.transfer(node, $.validators[moduleName][skippedIndex].bond);

        _decreaseNumberOfRegisteredValidators($, moduleName);
        unchecked {
            ++$.nextToBeProvisioned[moduleName];
        }
        emit ValidatorSkipped($.validators[moduleName][skippedIndex].pubKey, skippedIndex, moduleName);
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted to the DAO
     */
    function changeMinimumVTAmount(uint256 newMinimumVTAmount) external restricted {
        _changeMinimumVTAmount(newMinimumVTAmount);
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Initially it is restricted to the DAO
     */
    function createPufferModule(bytes32 moduleName) external restricted returns (address) {
        return _createPufferModule(moduleName);
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted to the DAO
     */
    function setModuleWeights(bytes32[] calldata newModuleWeights) external restricted {
        _setModuleWeights(newModuleWeights);
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted to the DAO
     */
    function setValidatorLimitPerModule(bytes32 moduleName, uint128 limit) external restricted {
        _setValidatorLimitPerModule(moduleName, limit);
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted to the DAO
     */
    function setVTPenalty(uint256 newPenaltyAmount) external restricted {
        _setVTPenalty(newPenaltyAmount);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getVTPenalty() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.vtPenalty;
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
     * @dev This is meant for OFF-CHAIN use, as it can be very expensive to call
     */
    function getValidators(bytes32 moduleName) external view returns (Validator[] memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 numOfValidators = $.pendingValidatorIndices[moduleName];

        Validator[] memory validators = new Validator[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; ++i) {
            validators[i] = $.validators[moduleName][i];
        }

        return validators;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getNextValidatorToProvision() public view returns (bytes32, uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 moduleSelectionIndex = $.moduleSelectIndex;
        uint256 moduleWeightsLength = $.moduleWeights.length;
        // Do Weights number of rounds
        uint256 moduleEndIndex = moduleSelectionIndex + moduleWeightsLength;

        // Read from the storage
        bytes32 moduleName = $.moduleWeights[moduleSelectionIndex % moduleWeightsLength];

        // Iterate through all modules to see if there is a validator ready to be provisioned
        while (moduleSelectionIndex < moduleEndIndex) {
            // Read the index for that moduleName
            uint256 pufferModuleIndex = $.nextToBeProvisioned[moduleName];

            // If we find it, return it
            if ($.validators[moduleName][pufferModuleIndex].status == Status.PENDING) {
                return (moduleName, pufferModuleIndex);
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
        return $.pendingValidatorIndices[moduleName];
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getValidatorInfo(bytes32 moduleName, uint256 pufferModuleIndex) external view returns (Validator memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.validators[moduleName][pufferModuleIndex];
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getNodeInfo(address node) external view returns (NodeInfo memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.nodeOperatorInfo[node];
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
     * @inheritdoc IPufferProtocol
     */
    function getValidatorTicketsBalance(address owner) public view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        return $.nodeOperatorInfo[owner].vtBalance;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getMinimumVtAmount() public view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.minimumVtAmount;
    }

    /**
     * @notice Returns necessary information to make Guardian's life easier
     */
    function getPayload(bytes32 moduleName, bool usingEnclave)
        external
        view
        returns (bytes[] memory, bytes memory, uint256, uint256)
    {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        bytes[] memory pubKeys = GUARDIAN_MODULE.getGuardiansEnclavePubkeys();
        bytes memory withdrawalCredentials = getWithdrawalCredentials(address($.modules[moduleName]));
        uint256 threshold = GUARDIAN_MODULE.getThreshold();
        uint256 validatorBond = usingEnclave ? _ENCLAVE_VALIDATOR_BOND : _NO_ENCLAVE_VALIDATOR_BOND;
        uint256 ethAmount = validatorBond + ($.minimumVtAmount * PUFFER_ORACLE.getValidatorTicketPrice()) / 1 ether;

        return (pubKeys, withdrawalCredentials, threshold, ethAmount);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function getModuleLimitInformation(bytes32 moduleName) external view returns (ModuleLimit memory info) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.moduleLimits[moduleName];
    }

    /**
     * @notice Called by the PufferModules to check if the system is paused
     * @dev `restricted` will revert if the system is paused
     */
    function revertIfPaused() external restricted { }

    function _storeValidatorInformation(
        ProtocolStorage storage $,
        ValidatorKeyData calldata data,
        uint256 pufETHAmount,
        bytes32 moduleName,
        uint256 vtAmount
    ) internal {
        uint256 pufferModuleIndex = $.pendingValidatorIndices[moduleName];

        // No need for SafeCast
        $.validators[moduleName][pufferModuleIndex] = Validator({
            pubKey: data.blsPubKey,
            status: Status.PENDING,
            module: address($.modules[moduleName]),
            bond: uint64(pufETHAmount),
            node: msg.sender
        });

        $.nodeOperatorInfo[msg.sender].vtBalance += SafeCast.toUint96(vtAmount);

        // Increment indices for this module and number of validators registered
        unchecked {
            ++$.nodeOperatorInfo[msg.sender].pendingValidatorCount;
            ++$.pendingValidatorIndices[moduleName];
            ++$.moduleLimits[moduleName].numberOfRegisteredValidators;
        }
        emit NumberOfActiveValidatorsChanged(moduleName, $.moduleLimits[moduleName].numberOfRegisteredValidators);
        emit ValidatorKeyRegistered(data.blsPubKey, pufferModuleIndex, moduleName, (data.raveEvidence.length > 0));
    }

    function _setValidatorLimitPerModule(bytes32 moduleName, uint128 limit) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        if (limit < $.moduleLimits[moduleName].numberOfRegisteredValidators) {
            revert ValidatorLimitForModuleReached();
        }
        emit ValidatorLimitPerModuleChanged($.moduleLimits[moduleName].allowedLimit, limit);
        $.moduleLimits[moduleName].allowedLimit = limit;
    }

    function _setVTPenalty(uint256 newPenaltyAmount) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        emit VTPenaltyChanged($.vtPenalty, newPenaltyAmount);
        $.vtPenalty = newPenaltyAmount;
    }

    function _setModuleWeights(bytes32[] memory newModuleWeights) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        emit ModuleWeightsChanged($.moduleWeights, newModuleWeights);
        $.moduleWeights = newModuleWeights;
    }

    function _createPufferModule(bytes32 moduleName) internal returns (address) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        if (address($.modules[moduleName]) != address(0)) {
            revert ModuleAlreadyExists();
        }
        IPufferModule module = PUFFER_MODULE_MANAGER.createNewPufferModule(moduleName);
        $.modules[moduleName] = module;
        $.moduleWeights.push(moduleName);
        bytes32 withdrawalCredentials = bytes32(module.getWithdrawalCredentials());
        emit NewPufferModuleCreated(address(module), moduleName, withdrawalCredentials);
        _setValidatorLimitPerModule(moduleName, 1000);
        return address(module);
    }

    function _checkValidatorRegistrationInputs(
        ProtocolStorage storage $,
        ValidatorKeyData calldata data,
        bytes32 moduleName
    ) internal view {
        // This acts as a validation if the module is existent
        // +1 is to validate the current transaction registration
        if (($.moduleLimits[moduleName].numberOfRegisteredValidators + 1) > $.moduleLimits[moduleName].allowedLimit) {
            revert ValidatorLimitForModuleReached();
        }

        if (data.blsPubKey.length != _BLS_PUB_KEY_LENGTH) {
            revert InvalidBLSPubKey();
        }

        if (data.blsEncryptedPrivKeyShares.length != GUARDIAN_MODULE.getGuardians().length) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeySet.length != (GUARDIAN_MODULE.getThreshold() * _BLS_PUB_KEY_LENGTH)) {
            revert InvalidBLSPublicKeySet();
        }
    }

    function _changeMinimumVTAmount(uint256 newMinimumVtAmount) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        emit MinimumVTAmountChanged($.minimumVtAmount, newMinimumVtAmount);
        $.minimumVtAmount = newMinimumVtAmount;
    }

    function _getBondBurnAmount(StoppedValidatorInfo calldata validatorInfo, uint256 validatorBondAmount)
        internal
        view
        returns (uint256 pufETHBurnAmount)
    {
        // Case 1:
        // The Validator was slashed, we burn the whole bond for that validator
        if (validatorInfo.wasSlashed) {
            return validatorBondAmount;
        }

        // Case 2:
        // The withdrawal amount is less than 32 ETH, we burn the difference to cover up the loss for inactivity
        if (validatorInfo.withdrawalAmount < 32 ether) {
            pufETHBurnAmount = PUFFER_VAULT.convertToSharesUp(32 ether - validatorInfo.withdrawalAmount);
        }
        // Case 3:
        // Withdrawal amount was >= 32 ether, we don't burn anything
        return pufETHBurnAmount;
    }

    function _validateSignaturesAndProvisionValidator(
        ProtocolStorage storage $,
        bytes32 moduleName,
        uint256 index,
        bytes[] calldata guardianEnclaveSignatures,
        bytes calldata validatorSignature
    ) internal {
        bytes memory validatorPubKey = $.validators[moduleName][index].pubKey;

        bytes memory withdrawalCredentials = getWithdrawalCredentials($.validators[moduleName][index].module);

        bytes32 depositDataRoot =
            LibBeaconchainContract.getDepositDataRoot(validatorPubKey, validatorSignature, withdrawalCredentials);

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateProvisionNode({
            pufferModuleIndex: index,
            pubKey: validatorPubKey,
            signature: validatorSignature,
            depositDataRoot: depositDataRoot,
            withdrawalCredentials: withdrawalCredentials,
            guardianEnclaveSignatures: guardianEnclaveSignatures
        });

        IPufferModule module = $.modules[moduleName];

        // Transfer 32 ETH to the module
        PUFFER_VAULT.transferETH(address(module), 32 ether);

        emit SuccessfullyProvisioned(validatorPubKey, index, moduleName);

        // Increase lockedETH on Puffer Oracle
        PUFFER_ORACLE.provisionNode();

        module.callStake({ pubKey: validatorPubKey, signature: validatorSignature, depositDataRoot: depositDataRoot });
    }

    function _getVTBurnAmount(StoppedValidatorInfo calldata validatorInfo) internal pure returns (uint256) {
        uint256 validatedEpochs = validatorInfo.endEpoch - validatorInfo.startEpoch;
        // Epoch has 32 blocks, each block is 12 seconds, we upscale to 18 decimals to get the VT amount and divide by 1 day
        // The formula is validatedEpochs * 32 * 12 * 1 ether / 1 days (4444444444444444.44444444...) we round it up
        return validatedEpochs * 4444444444444445;
    }

    function _callPermit(address token, Permit calldata permitData) internal {
        try IERC20Permit(token).permit({
            owner: msg.sender,
            spender: address(this),
            value: permitData.amount,
            deadline: permitData.deadline,
            v: permitData.v,
            s: permitData.s,
            r: permitData.r
        }) { } catch { }
    }

    function _decreaseNumberOfRegisteredValidators(ProtocolStorage storage $, bytes32 moduleName) internal {
        $.moduleLimits[moduleName].numberOfRegisteredValidators -= 1;
        emit NumberOfActiveValidatorsChanged(moduleName, $.moduleLimits[moduleName].numberOfRegisteredValidators);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
