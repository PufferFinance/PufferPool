// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";
import { IPufferModuleFactory } from "puffer/interface/IPufferModuleFactory.sol";
import { IPufferOracleV2 } from "pufETH/interface/IPufferOracleV2.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Permit } from "pufETH/structs/Permit.sol";
import { Status } from "puffer/struct/Status.sol";
import { ProtocolStorage, NodeInfo } from "puffer/struct/ProtocolStorage.sol";
import { LibBeaconchainContract } from "puffer/LibBeaconchainContract.sol";
import { MerkleProof } from "openzeppelin/utils/cryptography/MerkleProof.sol";
import { IERC20Permit } from "openzeppelin/token/ERC20/extensions/IERC20Permit.sol";
import { SafeCast } from "openzeppelin/utils/math/SafeCast.sol";
import { PufferVaultV2 } from "pufETH/PufferVaultV2.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { StoppedValidatorInfo } from "puffer/struct/StoppedValidatorInfo.sol";

/**
 * @title PufferProtocol
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferProtocol is IPufferProtocol, AccessManagedUpgradeable, UUPSUpgradeable, PufferProtocolStorage {
    /**
     * @dev Validator ticket loss rate per second
     */
    uint256 internal constant _VT_LOSS_RATE_PER_SECOND = 11574074074075; // (1 ether / 1 days) rounded up

    /**
     * @dev Validator ticket loss rate per second
     */
    uint256 internal constant _VT_LOSS_RATE_PER_SECOND_DOWN = 11574074074074; // (1 ether / 1 days) rounded down

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
    IPufferModuleFactory public immutable override PUFFER_MODULE_FACTORY;

    /**
     * @inheritdoc IPufferProtocol
     */
    IPufferOracleV2 public immutable override PUFFER_ORACLE;

    constructor(
        PufferVaultV2 pufferVault,
        IGuardianModule guardianModule,
        address moduleFactory,
        ValidatorTicket validatorTicket,
        IPufferOracleV2 oracle
    ) {
        GUARDIAN_MODULE = guardianModule;
        PUFFER_VAULT = PufferVaultV2(payable(address(pufferVault)));
        PUFFER_MODULE_FACTORY = IPufferModuleFactory(moduleFactory);
        VALIDATOR_TICKET = validatorTicket;
        PUFFER_ORACLE = oracle;
        _disableInitializers();
    }

    function initialize(address accessManager, address noRestakingModule) external initializer {
        __AccessManaged_init(accessManager);
        _setValidatorLimitPerModule(_NO_RESTAKING, type(uint128).max);
        bytes32[] memory weights = new bytes32[](1);
        weights[0] = _NO_RESTAKING;
        _setModuleWeights(weights);
        _changeModule(_NO_RESTAKING, IPufferModule(noRestakingModule));
        _changeMinimumVTAmount(28 ether); // 28 Validator Tickets
        _setVTPenalty(10 ether); // 10 Validator Tickets
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function depositValidatorTickets(Permit calldata permit, address node) external restricted {
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

        _updateVTBalance($, node, 0);

        $.nodeOperatorInfo[node].vtBalance += SafeCast.toUint96(permit.amount);
        emit ValidatorTicketsDeposited(node, msg.sender, permit.amount);
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function withdrawValidatorTickets(uint96 amount, address recipient) external restricted {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        $.nodeOperatorInfo[msg.sender].vtBalance -= amount;

        _updateVTBalance($, msg.sender, 0);

        // The user must have at least `minimumVtAmount` VT for each active validator
        uint256 mandatoryVTAmount = (
            $.nodeOperatorInfo[msg.sender].activeValidatorCount + $.nodeOperatorInfo[msg.sender].pendingValidatorCount
        ) * $.minimumVtAmount;
        // If the remaining VT balance is less than the mandatory amount, revert
        if ($.nodeOperatorInfo[msg.sender].vtBalance < mandatoryVTAmount) {
            revert InvalidValidatorTicketAmount(amount, mandatoryVTAmount);
        }

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
        uint256 numberOfDays,
        Permit calldata pufETHPermit,
        Permit calldata vtPermit
    ) external payable restricted {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        // Upscale number of days to 18 decimals
        if ((numberOfDays * 1 ether) < $.minimumVtAmount) {
            revert InvalidData();
        }

        // Revert if the permit amounts are non zero, but the msg.value is also non zero
        if (vtPermit.amount != 0 && pufETHPermit.amount != 0 && msg.value > 0) {
            revert InvalidETHAmount();
        }

        _checkValidatorRegistrationInputs({ $: $, data: data, moduleName: moduleName });

        uint256 validatorBond = data.raveEvidence.length > 0 ? _ENCLAVE_VALIDATOR_BOND : _NO_ENCLAVE_VALIDATOR_BOND;
        // convertToShares is rounding down, @todo double check if we care for this case
        uint256 bondInPufETH = PUFFER_VAULT.convertToShares(validatorBond);
        uint256 vtPayment = PUFFER_ORACLE.getValidatorTicketPrice() * numberOfDays;

        // If the user overpaid
        if (msg.value > (validatorBond + vtPayment)) {
            revert InvalidETHAmount();
        }

        uint256 pufETHMinted;

        // If the VT permit amount is zero, that means that the user is paying for VT with ETH
        if (vtPermit.amount == 0) {
            VALIDATOR_TICKET.purchaseValidatorTicket{ value: vtPayment }(address(this));
        } else {
            _callPermit(address(VALIDATOR_TICKET), vtPermit);
            // slither-disable-next-line unchecked-transfer
            VALIDATOR_TICKET.transferFrom(msg.sender, address(this), numberOfDays * 1 ether); // * 1 ether is to upscale amount to 18 decimals
        }

        // If the pufETH permit amount is zero, that means that the user is paying the bond with ETH
        if (pufETHPermit.amount == 0) {
            pufETHMinted = PUFFER_VAULT.depositETH{ value: validatorBond }(address(this));
        } else {
            _callPermit(address(PUFFER_VAULT), pufETHPermit);
            // slither-disable-next-line unchecked-transfer
            PUFFER_VAULT.transferFrom(msg.sender, address(this), bondInPufETH);
        }

        // Store the bond amount
        uint256 bondAmount = pufETHMinted > 0 ? pufETHMinted : bondInPufETH;

        _storeValidatorInformation({
            $: $,
            data: data,
            pufETHAmount: bondAmount,
            moduleName: moduleName,
            numberOfDays: numberOfDays
        });
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function provisionNode(
        bytes[] calldata guardianEnclaveSignatures,
        bytes calldata validatorSignature,
        uint88 vtBurnOffset
    ) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        (bytes32 moduleName, uint256 index) = getNextValidatorToProvision();

        // Increment next validator to be provisioned index, panics if there is no validator for provisioning
        $.nextToBeProvisioned[moduleName] = index + 1;
        unchecked {
            // Increment module selection index
            ++$.moduleSelectIndex;
        }
        // Validator Tickets Accounting
        _provisionNodeVTUpdate({ $: $, moduleName: moduleName, index: index, vtQueueOffset: vtBurnOffset });

        _validateSignaturesAndProvisionValidator({
            $: $,
            moduleName: moduleName,
            index: index,
            vtBurnOffset: vtBurnOffset,
            guardianEnclaveSignatures: guardianEnclaveSignatures,
            validatorSignature: validatorSignature
        });

        // Mark the validator as active
        $.validators[moduleName][index].status = Status.ACTIVE;
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function retrieveBond(StoppedValidatorInfo calldata validatorInfo, bytes32[] calldata merkleProof) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        Validator storage validator = $.validators[validatorInfo.moduleName][validatorInfo.validatorIndex];

        if (validator.status != Status.ACTIVE) {
            revert InvalidValidatorState(validator.status);
        }

        if (
            // Leaf
            !MerkleProof.verifyCalldata(
                merkleProof,
                $.fullWithdrawalsRoots[validatorInfo.blockNumber],
                keccak256(
                    bytes.concat(
                        keccak256(
                            abi.encode(
                                validatorInfo.moduleName,
                                validatorInfo.validatorIndex,
                                validatorInfo.withdrawalAmount,
                                validatorInfo.validatorStopTimestamp,
                                validatorInfo.wasSlashed
                            )
                        )
                    )
                )
            )
        ) {
            revert InvalidMerkleProof();
        }
        // Store what we need
        uint256 returnAmount = validator.bond;
        address node = validator.node;
        bytes memory pubKey = validator.pubKey;

        _updateStopValidatorVTBalance({
            $: $,
            moduleName: validatorInfo.moduleName,
            index: validatorInfo.validatorIndex,
            validatorStopTimestamp: validatorInfo.validatorStopTimestamp
        });
        // Remove what we don't
        delete validator.module;
        delete validator.node;
        delete validator.bond;
        delete validator.pubKey;
        validator.status = Status.EXITED;
        // Decrease the validator number for that module
        $.moduleLimits[validatorInfo.moduleName].numberOfActiveValidators -= 1;

        // Burn everything if the validator was slashed
        if (validatorInfo.wasSlashed) {
            PUFFER_VAULT.burn(returnAmount);
        } else {
            uint256 burnAmount = 0;

            if (validatorInfo.withdrawalAmount < 32 ether) {
                //@todo rounding down, recheck
                burnAmount = PUFFER_VAULT.previewDeposit(32 ether - validatorInfo.withdrawalAmount);
                PUFFER_VAULT.burn(burnAmount);
            }

            // slither-disable-next-line unchecked-transfer
            PUFFER_VAULT.transfer(node, (returnAmount - burnAmount));
        }

        emit ValidatorExited(pubKey, validatorInfo.validatorIndex, validatorInfo.moduleName);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function skipProvisioning(bytes32 moduleName, bytes[] calldata guardianEOASignatures) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        uint256 skippedIndex = $.nextToBeProvisioned[moduleName];

        address node = $.validators[moduleName][skippedIndex].node;

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateSkipProvisioning({
            moduleName: moduleName,
            skippedIndex: skippedIndex,
            guardianEOASignatures: guardianEOASignatures
        });

        _penalizeNodeOperator(node);

        // Change the status of that validator
        $.validators[moduleName][skippedIndex].status = Status.SKIPPED;

        // Transfer pufETH to that node operator
        // slither-disable-next-line unchecked-transfer
        PUFFER_VAULT.transfer(node, $.validators[moduleName][skippedIndex].bond);

        unchecked {
            ++$.nextToBeProvisioned[moduleName];
        }
        emit ValidatorSkipped($.validators[moduleName][skippedIndex].pubKey, skippedIndex, moduleName);
    }

    /**
     * @notice Posts the full withdrawals root
     * @param root is the Merkle Root hash
     * @param blockNumber is the block number of a withdrawal root
     */
    function postFullWithdrawalsRoot(bytes32 root, uint256 blockNumber, bytes[] calldata guardianSignatures) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        // Prevent double posting of the same root
        if ($.fullWithdrawalsRoots[blockNumber] != bytes32(0)) {
            revert InvalidData();
        }

        // Prevent double posting of the same root
        if ($.fullWithdrawalsRoots[blockNumber] != bytes32(0)) {
            revert InvalidData();
        }

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validatePostFullWithdrawalsRoot({
            root: root,
            blockNumber: blockNumber,
            guardianSignatures: guardianSignatures
        });

        $.fullWithdrawalsRoots[blockNumber] = root;

        emit FullWithdrawalsRootPosted(blockNumber, root);
    }

    /**
     * @inheritdoc IPufferProtocol
     * @dev Restricted to the DAO
     */
    function changeModule(bytes32 moduleName, IPufferModule newModule) external restricted {
        _changeModule(moduleName, newModule);
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
    function createPufferModule(bytes32 moduleName, string calldata metadataURI, address delegationApprover)
        external
        restricted
        returns (address)
    {
        return _createPufferModule(moduleName, metadataURI, delegationApprover);
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
        // Do Weights number of rounds
        uint256 moduleEndIndex = moduleSelectionIndex + $.moduleWeights.length;
        uint256 moduleWeightsLength = $.moduleWeights.length;

        // Read from the storage
        bytes32 moduleName = $.moduleWeights[moduleSelectionIndex % moduleWeightsLength];

        // Iterate through all modules to see if there is a validator ready to be provisioned
        while (moduleSelectionIndex < moduleEndIndex) {
            // Read the index for that moduleName
            uint256 validatorIndex = $.nextToBeProvisioned[moduleName];

            // If we find it, return it
            if ($.validators[moduleName][validatorIndex].status == Status.PENDING) {
                return (moduleName, validatorIndex);
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
    function getValidatorInfo(bytes32 moduleName, uint256 validatorIndex) external view returns (Validator memory) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return $.validators[moduleName][validatorIndex];
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

        NodeInfo memory nodeInfo = $.nodeOperatorInfo[owner];

        // We only care about the time difference
        uint256 elapsedTime = block.timestamp > nodeInfo.lastUpdate
            ? block.timestamp - nodeInfo.lastUpdate
            : nodeInfo.lastUpdate - block.timestamp;

        uint256 calculatedBalance = (nodeInfo.vtBalance + nodeInfo.virtualVTBalance)
            - (_VT_LOSS_RATE_PER_SECOND * elapsedTime * nodeInfo.activeValidatorCount);

        return calculatedBalance;
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
    function getPayload(bytes32 moduleName, bool usingEnclave, uint256 numberOfDays)
        external
        view
        returns (bytes[] memory, bytes memory, uint256, uint256)
    {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        bytes[] memory pubKeys = GUARDIAN_MODULE.getGuardiansEnclavePubkeys();
        bytes memory withdrawalCredentials = getWithdrawalCredentials(address($.modules[moduleName]));
        uint256 threshold = GUARDIAN_MODULE.getThreshold();
        uint256 validatorBond = usingEnclave ? _ENCLAVE_VALIDATOR_BOND : _NO_ENCLAVE_VALIDATOR_BOND;
        uint256 ethAmount = validatorBond + PUFFER_ORACLE.getValidatorTicketPrice() * numberOfDays;

        return (pubKeys, withdrawalCredentials, threshold, ethAmount);
    }

    function _storeValidatorInformation(
        ProtocolStorage storage $,
        ValidatorKeyData calldata data,
        uint256 pufETHAmount,
        bytes32 moduleName,
        uint256 numberOfDays
    ) internal {
        uint256 validatorIndex = $.pendingValidatorIndices[moduleName];

        // No need for SafeCast
        $.validators[moduleName][validatorIndex] = Validator({
            pubKey: data.blsPubKey,
            status: Status.PENDING,
            module: address($.modules[moduleName]),
            bond: uint64(pufETHAmount),
            node: msg.sender
        });

        $.nodeOperatorInfo[msg.sender].vtBalance += SafeCast.toUint96(numberOfDays * 1 ether); // upscale to 18 decimals

        // Increment indices for this module and number of validators registered
        unchecked {
            ++$.nodeOperatorInfo[msg.sender].pendingValidatorCount;
            ++$.pendingValidatorIndices[moduleName];
            ++$.moduleLimits[moduleName].numberOfActiveValidators;
        }

        emit ValidatorKeyRegistered(data.blsPubKey, validatorIndex, moduleName, (data.raveEvidence.length > 0));
    }

    function _setValidatorLimitPerModule(bytes32 moduleName, uint128 limit) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
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

    function _createPufferModule(bytes32 moduleName, string calldata metadataURI, address delegationApprover)
        internal
        returns (address)
    {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        if (address($.modules[moduleName]) != address(0)) {
            revert ModuleAlreadyExists();
        }
        IPufferModule module = PUFFER_MODULE_FACTORY.createNewPufferModule(moduleName, metadataURI, delegationApprover);
        $.modules[moduleName] = module;
        emit NewPufferModuleCreated(address(module));
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
        if (($.moduleLimits[moduleName].numberOfActiveValidators + 1) > $.moduleLimits[moduleName].allowedLimit) {
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

    function _changeModule(bytes32 moduleName, IPufferModule newModule) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        IPufferModule oldModule = $.modules[moduleName];
        if (address(oldModule) != address(0)) {
            revert InvalidPufferModule();
        }
        $.modules[moduleName] = newModule;
        emit ModuleChanged(moduleName, address(oldModule), address(newModule));
    }

    function _changeMinimumVTAmount(uint256 newMinimumVtAmount) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        emit MinimumVTAmountChanged($.minimumVtAmount, newMinimumVtAmount);
        $.minimumVtAmount = newMinimumVtAmount;
    }

    function _validateSignaturesAndProvisionValidator(
        ProtocolStorage storage $,
        bytes32 moduleName,
        uint256 index,
        uint256 vtBurnOffset,
        bytes[] calldata guardianEnclaveSignatures,
        bytes calldata validatorSignature
    ) internal {
        bytes memory validatorPubKey = $.validators[moduleName][index].pubKey;

        bytes memory withdrawalCredentials = getWithdrawalCredentials($.validators[moduleName][index].module);

        bytes32 depositDataRoot = this.getDepositDataRoot({
            pubKey: validatorPubKey,
            signature: validatorSignature,
            withdrawalCredentials: withdrawalCredentials
        });

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateProvisionNode({
            validatorIndex: index,
            vtBurnOffset: vtBurnOffset,
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

    /**
     * @dev When the node operator registers a new validator, the VT balance is updated
     * Because the entry queue varies, the guardians will credit node operator with the virtual VT's.
     * That means that the VT decay will start when the provisioning happens, but because the node operator is credited
     * Virtual VT's by the guardians, the end result will be the same.
     */
    function _provisionNodeVTUpdate(ProtocolStorage storage $, bytes32 moduleName, uint256 index, uint88 vtQueueOffset)
        internal
    {
        address node = $.validators[moduleName][index].node;

        _updateVTBalance($, node, vtQueueOffset);

        --$.nodeOperatorInfo[node].pendingValidatorCount;
        ++$.nodeOperatorInfo[node].activeValidatorCount;
    }

    /**
     * @dev When the node operator gets ejected / exits a validator, the node operator continues to lose VT.
     * When the retrieveBond is called, we will credit that node operator with virtual VT's that can't be redeemed.
     * If the node operator wants to retrieve unspent VT's and the bond, they are incentivized to do so as soon as possible.
     */
    function _updateStopValidatorVTBalance(
        ProtocolStorage storage $,
        bytes32 moduleName,
        uint256 index,
        uint256 validatorStopTimestamp
    ) internal {
        address node = $.validators[moduleName][index].node;

        uint88 vtToCredit = 0;

        // If the lastUpdate is bigger, we need to credit the node operator with virtual VT's, because we counted his validator as `active` and burned his VT
        if (validatorStopTimestamp < $.nodeOperatorInfo[node].lastUpdate) {
            vtToCredit = SafeCast.toUint88(
                ($.nodeOperatorInfo[node].lastUpdate - validatorStopTimestamp) * _VT_LOSS_RATE_PER_SECOND_DOWN
            );
        }

        // But we credit the `vtToCredit` to the node operator
        _updateVTBalance($, node, vtToCredit);

        $.nodeOperatorInfo[node].activeValidatorCount -= 1;
    }

    function _updateVTBalance(ProtocolStorage storage $, address node, uint88 vtQueueOffset) internal {
        uint256 oldVTBalance = $.nodeOperatorInfo[node].vtBalance;
        uint256 oldVirtualVTBalance = $.nodeOperatorInfo[node].virtualVTBalance;

        uint256 totalOldVTBalance = oldVTBalance + oldVirtualVTBalance;

        // Returns the new total balance
        uint256 newVTBalance = getValidatorTicketsBalance(node);

        $.nodeOperatorInfo[node].virtualVTBalance += vtQueueOffset;

        uint256 burnedAmount = _burnVt($, node, totalOldVTBalance, newVTBalance);

        uint256 realVTBalance = oldVTBalance - burnedAmount;

        // Update the node information
        $.nodeOperatorInfo[node].lastUpdate = uint48(block.timestamp);
        $.nodeOperatorInfo[node].vtBalance = SafeCast.toUint96(realVTBalance);
        emit VTBalanceChanged({
            node: node,
            oldVTBalance: oldVTBalance,
            newVTBalance: realVTBalance,
            oldVirtualVTBalance: oldVirtualVTBalance,
            newVirtualVTBalance: $.nodeOperatorInfo[node].virtualVTBalance
        });
    }

    /**
     * @dev Burns the VT's from `node` and returns the amount burned
     * newVTBalance can be bigger than `totalOldVTBalance`  because of the virtual VT's that we give to the node operator
     */
    function _burnVt(ProtocolStorage storage $, address node, uint256 totalOldVTBalance, uint256 newVTBalance)
        internal
        returns (uint256)
    {
        // The diff is the amount to burn
        uint256 toBurn =
            totalOldVTBalance > newVTBalance ? (totalOldVTBalance - newVTBalance) : (newVTBalance - totalOldVTBalance);

        uint256 virtualVTBalance = $.nodeOperatorInfo[node].virtualVTBalance;

        // First, try to deduct from the virtual VT balance
        if (toBurn <= virtualVTBalance) {
            $.nodeOperatorInfo[node].virtualVTBalance -= SafeCast.toUint88(toBurn);
            return 0;
        }

        // If the virtual VT balance is not enough, we first deduct from the virtual VT balance, and then burn from the VT balance
        toBurn -= virtualVTBalance;
        $.nodeOperatorInfo[node].virtualVTBalance = 0;
        VALIDATOR_TICKET.burn(toBurn);
        return toBurn;
    }

    function _penalizeNodeOperator(address node) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        VALIDATOR_TICKET.burn($.vtPenalty);

        $.nodeOperatorInfo[node].vtBalance -= SafeCast.toUint96($.vtPenalty);
        --$.nodeOperatorInfo[node].pendingValidatorCount;

        _updateVTBalance($, node, 0);
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

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
