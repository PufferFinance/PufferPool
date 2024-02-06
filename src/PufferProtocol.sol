// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";
import { IPufferModuleFactory } from "puffer/interface/IPufferModuleFactory.sol";
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Permit } from "puffer/struct/Permit.sol";
import { Status } from "puffer/struct/Status.sol";
import { ProtocolStorage } from "puffer/struct/ProtocolStorage.sol";
import { PufferPoolStorage } from "puffer/struct/PufferPoolStorage.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { LibBeaconchainContract } from "puffer/LibBeaconchainContract.sol";
import { MerkleProof } from "openzeppelin/utils/cryptography/MerkleProof.sol";
import { IERC20Permit } from "openzeppelin/token/ERC20/extensions/IERC20Permit.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { SafeCastLib } from "solady/utils/SafeCastLib.sol";
import { PufferVaultMainnet } from "pufETH/PufferVaultMainnet.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { IWETH } from "pufETH/interface/Other/IWETH.sol";

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
     * 3600 * 12(avg block time) = 43200 seconds
     * 43200 seconds ~ 12 hours
     */
    uint256 internal constant _UPDATE_INTERVAL = 3600;

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
    ValidatorTicket public immutable VALIDATOR_TICKET;

    /**
     * @inheritdoc IPufferProtocol
     */
    PufferVaultMainnet public immutable PUFFER_VAULT;

    IWETH public immutable WETH; //@todo figure if we need it

    /**
     * @inheritdoc IPufferProtocol
     */
    IPufferModuleFactory public immutable override PUFFER_MODULE_FACTORY;

    IPufferOracle public immutable PUFFER_ORACLE;

    constructor(
        PufferVaultMainnet pufferVault,
        IWETH weth,
        IGuardianModule guardianModule,
        address payable treasury,
        address moduleFactory,
        ValidatorTicket validatorTicket,
        IPufferOracle oracle
    ) payable {
        TREASURY = treasury;
        GUARDIAN_MODULE = guardianModule;
        PUFFER_VAULT = PufferVaultMainnet(payable(address(pufferVault)));
        WETH = weth;
        PUFFER_MODULE_FACTORY = IPufferModuleFactory(moduleFactory);
        VALIDATOR_TICKET = validatorTicket;
        PUFFER_ORACLE = oracle;
        _disableInitializers();
    }

    receive() external payable { }

    function initialize(address accessManager, address noRestakingModule) external initializer {
        __AccessManaged_init(accessManager);
        _setValidatorLimitPerInterval(20);
        _setValidatorLimitPerModule(_NO_RESTAKING, type(uint128).max);
        bytes32[] memory weights = new bytes32[](1);
        weights[0] = _NO_RESTAKING;
        _setModuleWeights(weights);
        _changeModule(_NO_RESTAKING, IPufferModule(noRestakingModule));
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        $.numberOfActiveValidators = uint128(10000);
        // Start at 1 (gas optimisation)
        $.numberOfValidatorsRegisteredInThisInterval = uint16(1);
    }

    /**
     * @notice Deposits validator tickets for the `node`
     */
    function depositValidatorTicket(Permit calldata permit, address node) external {
        try IERC20Permit(address(VALIDATOR_TICKET)).permit({
            owner: msg.sender,
            spender: address(this),
            value: permit.amount,
            deadline: permit.deadline,
            v: permit.v,
            s: permit.s,
            r: permit.r
        }) { } catch { }

        VALIDATOR_TICKET.transferFrom(msg.sender, address(this), permit.amount);

        ProtocolStorage storage $ = _getPufferProtocolStorage();
        $.vtBalances[node].vtBalance += SafeCastLib.toUint128(permit.amount);
        emit ValidatorTicketsDeposited(node, msg.sender, permit.amount);
    }

    function withdrawValidatorTicket(uint256 amount, address recipient) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        //@todo restrict how much of VT can be withdrawn based on the validator number

        $.vtBalances[msg.sender].vtBalance -= SafeCastLib.toUint128(amount);
        emit ValidatorTicketsWithdrawn(msg.sender, recipient, amount);
    }

    /**
     * @notice Used to register validator key
     * @dev Permit for VT and pufETH is optional, if you do the normal .approve(address(this))
     * Both permits will revert but the transaction overall will succeed, as .transferFrom will not revert in that case
     */
    function registerValidatorKey(
        ValidatorKeyData calldata data,
        bytes32 moduleName,
        uint256 numberOfDays,
        Permit calldata pufETHPermit,
        Permit calldata vtPermit
    ) external payable restricted {
        //@todo what is the min amount?
        if (numberOfDays < 28) {
            revert InvalidData();
        }

        // Revert if the permit amounts are non zero, but the msg.value is also non zero
        if (vtPermit.amount != 0 && pufETHPermit.amount != 0 && msg.value > 0) {
            revert InvalidETHAmount();
        }

        ProtocolStorage storage $ = _getPufferProtocolStorage();

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
            VALIDATOR_TICKET.transferFrom(msg.sender, address(this), numberOfDays * 1 ether); // * 1 ether is to upscale amount to 18 decimals
        }

        // If the pufETH permit amount is zero, that means that the user is paying the bond with ETH
        if (pufETHPermit.amount == 0) {
            pufETHMinted = PUFFER_VAULT.depositETH{ value: validatorBond }(address(this));
        } else {
            _callPermit(address(PUFFER_VAULT), pufETHPermit);
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

    function isOverBurstThreshold() external view returns (bool) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return (($.activePufferValidators * 100 / $.numberOfActiveValidators) > _BURST_THRESHOLD);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function provisionNode(bytes[] calldata guardianEnclaveSignatures) external {
        ProtocolStorage storage $ = _getPufferProtocolStorage();

        (bytes32 moduleName, uint256 index) = getNextValidatorToProvision();

        bytes memory validatorPubKey = $.validators[moduleName][index].pubKey;
        bytes memory validatorSignature = $.validators[moduleName][index].signature;

        // Increment next validator to be provisioned index, overflows if there is no validator for provisioning
        $.nextToBeProvisioned[moduleName] = index + 1;
        unchecked {
            // Increment module selection index
            ++$.moduleSelectIndex;
        }

        bytes memory withdrawalCredentials = getWithdrawalCredentials($.validators[moduleName][index].module);

        bytes32 depositDataRoot = this.getDepositDataRoot({
            pubKey: validatorPubKey,
            signature: validatorSignature,
            withdrawalCredentials: withdrawalCredentials
        });

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateProvisionNode({
            validatorIndex: index,
            pubKey: validatorPubKey,
            signature: validatorSignature,
            depositDataRoot: depositDataRoot,
            withdrawalCredentials: withdrawalCredentials,
            guardianEnclaveSignatures: guardianEnclaveSignatures
        });

        $.validators[moduleName][index].status = Status.ACTIVE;

        IPufferModule module = $.modules[moduleName];

        // Transfer 32 ETH to the module
        PUFFER_VAULT.transferETH(address(module), 32 ether);

        emit SuccessfullyProvisioned(validatorPubKey, index, moduleName);

        module.callStake({ pubKey: validatorPubKey, signature: validatorSignature, depositDataRoot: depositDataRoot });
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
        PUFFER_VAULT.transfer(validator.node, validator.bond);
    }

    /**
     * @inheritdoc IPufferProtocol
     */
    function retrieveBond(
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

        bytes32 withdrawalRoot = $.fullWithdrawalsRoots[blockNumber];

        if (
            // Leaf
            !MerkleProof.verifyCalldata(
                merkleProof,
                withdrawalRoot,
                keccak256(bytes.concat(keccak256(abi.encode(moduleName, validatorIndex, withdrawalAmount, wasSlashed))))
            )
        ) {
            revert InvalidMerkleProof();
        }
        // Store what we need
        uint256 returnAmount = validator.bond;
        address node = validator.node;
        bytes memory pubKey = validator.pubKey;

        // Remove what we don't
        delete validator.module;
        delete validator.node;
        delete validator.bond;
        delete validator.pubKey;
        delete validator.signature;
        validator.status = Status.EXITED;
        $.activePufferValidators -= 1;
        $.moduleLimits[moduleName].numberOfActiveValidators -= 1;

        // Burn everything if the validator was slashed
        if (wasSlashed) {
            PUFFER_VAULT.burn(PUFFER_VAULT.convertToShares(returnAmount));
        } else {
            uint256 burnAmount = 0;

            if (withdrawalAmount < 32 ether) {
                burnAmount = PUFFER_VAULT.previewDeposit(32 ether - withdrawalAmount);
                PUFFER_VAULT.burn(PUFFER_VAULT.convertToShares(burnAmount));
            }

            // slither-disable-next-line unchecked-transfer
            PUFFER_VAULT.transfer(node, (returnAmount - burnAmount));
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
        PUFFER_VAULT.transfer($.validators[moduleName][skippedIndex].node, $.validators[moduleName][skippedIndex].bond);

        unchecked {
            ++$.nextToBeProvisioned[moduleName];
        }
        emit ValidatorSkipped($.validators[moduleName][skippedIndex].pubKey, skippedIndex, moduleName);
    }

    /**
     * @notice Posts the full withdrawals root
     * @param root is the Merkle Root hash
     * @param blockNumber is the block number of a withdrawal root
     * @param modules is the array from which modules we are redistributing ETH
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

        // Allocate ETH capital back to the Vault ASAP to fuel Vault growth
        for (uint256 i = 0; i < modules.length; ++i) {
            // slither-disable-next-line calls-loop
            IPufferModule(modules[i]).call(address(PUFFER_VAULT), amounts[i], "");
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
        PufferPoolStorage storage $ = _getPufferPoolStorage();

        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateProofOfReserve({
            ethAmount: ethAmount,
            lockedETH: lockedETH,
            pufETHTotalSupply: pufETHTotalSupply,
            blockNumber: blockNumber,
            numberOfActiveValidators: numberOfActiveValidators,
            guardianSignatures: guardianSignatures
        });

        if ((block.number - $.lastUpdate) < _UPDATE_INTERVAL) {
            revert OutsideUpdateWindow();
        }

        $.ethAmount = ethAmount;
        $.lockedETH = lockedETH;
        $.pufETHTotalSupply = pufETHTotalSupply;
        $.lastUpdate = block.number;

        ProtocolStorage storage protocolStorage = _getPufferProtocolStorage();
        // gas optimization to skip zero value
        protocolStorage.numberOfValidatorsRegisteredInThisInterval = 1;
        protocolStorage.numberOfActiveValidators = uint128(numberOfActiveValidators);

        emit BackingUpdated(ethAmount, lockedETH, pufETHTotalSupply, blockNumber);
    }

    /**
     * @inheritdoc IPufferProtocol
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
    function setValidatorLimitPerModule(bytes32 moduleName, uint128 limit) external restricted {
        _setValidatorLimitPerModule(moduleName, limit);
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
    function getValidatorLimitPerInterval() external view returns (uint256) {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        return uint256($.validatorLimitPerInterval);
    }

    /**
     * @inheritdoc IPufferProtocol
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
            signature: data.signature,
            status: Status.PENDING,
            module: address($.modules[moduleName]),
            bond: uint64(pufETHAmount),
            node: msg.sender
        });

        $.vtBalances[msg.sender].vtBalance += SafeCastLib.toUint128(numberOfDays);

        // Increment indices for this module and number of validators registered
        unchecked {
            ++$.vtBalances[msg.sender].validatorCount;
            ++$.pendingValidatorIndices[moduleName];
            ++$.moduleLimits[moduleName].numberOfActiveValidators;
            ++$.numberOfValidatorsRegisteredInThisInterval;
            ++$.activePufferValidators;
        }

        emit ValidatorKeyRegistered(data.blsPubKey, validatorIndex, moduleName, (data.raveEvidence.length > 0));
    }

    function _setValidatorLimitPerModule(bytes32 moduleName, uint128 limit) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldLimit = $.moduleLimits[moduleName].allowedLimit;
        $.moduleLimits[moduleName].allowedLimit = limit;
        emit ValidatorLimitPerModuleChanged(oldLimit, limit);
    }

    // _sendETH is sending ETH to trusted addresses (no reentrancy)
    function _sendETH(address to, uint256 amount, uint256 rate) internal returns (uint256 toSend) {
        toSend = FixedPointMathLib.fullMulDiv(amount, rate, _ONE_HUNDRED_WAD);

        if (toSend != 0) {
            emit TransferredETH(to, toSend);
            to.safeTransferETH(toSend);
        }
    }

    function _setModuleWeights(bytes32[] memory newModuleWeights) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        bytes32[] memory oldModuleWeights = $.moduleWeights;
        $.moduleWeights = newModuleWeights;
        emit ModuleWeightsChanged(oldModuleWeights, newModuleWeights);
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

    function _setValidatorLimitPerInterval(uint256 newLimit) internal {
        ProtocolStorage storage $ = _getPufferProtocolStorage();
        uint256 oldLimit = uint256($.validatorLimitPerInterval);
        $.validatorLimitPerInterval = SafeCastLib.toUint16(newLimit);
        emit ValidatorLimitPerIntervalChanged(oldLimit, newLimit);
    }

    function _checkValidatorRegistrationInputs(
        ProtocolStorage storage $,
        ValidatorKeyData calldata data,
        bytes32 moduleName
    ) internal view {
        // validatorLimitPerInterval starts at 1, and +1 is to include check if the current registration will go over the limit
        if (($.numberOfValidatorsRegisteredInThisInterval + 1) > $.validatorLimitPerInterval + 1) {
            revert ValidatorLimitPerIntervalReached();
        }

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
