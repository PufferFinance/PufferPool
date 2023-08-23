// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20PermitUpgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "openzeppelin-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { OwnableUpgradeable } from "openzeppelin-upgradeable/access/OwnableUpgradeable.sol";
import { PausableUpgradeable } from "openzeppelin-upgradeable/security/PausableUpgradeable.sol";
import { SafeDeployer } from "puffer/SafeDeployer.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IPufferOwner } from "puffer/interface/IPufferOwner.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { EnclaveVerifier, IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { RaveEvidence } from "puffer/interface/RaveEvidence.sol";

/**
 * @title PufferPool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */

contract PufferPool is
    IPufferPool,
    IPufferOwner,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    ERC20PermitUpgradeable,
    SafeDeployer
{
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /**
     * @notice Address of the Eigen pod proxy beacon
     */
    address public immutable EIGEN_POD_PROXY_BEACON;

    /**
     * @notice Address of the Eigen Pod Manager
     */
    IEigenPodManager public immutable EIGEN_POD_MANAGER;

    /**
     * @dev ETH Amount required for becoming a Validator
     */
    uint256 internal constant _32_ETHER = 32 ether;

    /**
     * @dev EigenLayer's beacon chain strategy address
     */
    IStrategy internal constant _beaconChainETHStrategy = IStrategy(0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0);

    /**
     * @dev Index of the beacon ETH strategy
     */
    uint256 internal constant _beaconChainETHStrategyIndex = 0;

    /**
     * @dev Constant representing 100%
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * 1e18;

    /**
     * @dev Minimum deposit amount in ETH
     */
    uint256 internal constant _MINIMUM_DEPOSIT_AMOUNT = 0.01 ether;

    /**
     * @dev Locked ETH amount
     */
    uint256 internal _lockedETHAmount;

    /**
     * @dev New rewards amount
     */
    uint256 internal _newETHRewardsAmount;

    /**
     * @dev Guardians multisig wallet
     */
    Safe internal _guardiansMultisig;

    /**
     * @dev EigenPodProxy -> EigenPodProxyInformation
     */
    mapping(address => EigenPodProxyInformation) internal _eigenPodProxies;

    /**
     * @dev Actively validated services (AVSs) configuration
     */
    mapping(address => AVSParams) internal _allowedAVSs;

    /**
     * @dev Address of the {Safe} proxy factory
     */
    address internal _safeProxyFactory;

    /**
     * @dev Address of the {Safe} implementation contract
     */
    address internal _safeImplementation;

    /**
     * @dev Address of the Puffer AVS contract
     */
    address internal _pufferAvsAddress;

    /**
     * @dev Number of shares out of one billion to split AVS rewards with the pool
     */
    uint256 internal _avsCommission;

    /**
     * @dev Number of shares out of one billion to split consensus rewards with the pool
     */
    uint256 internal _consensusCommission;

    /**
     * @dev Number of shares out of one billion to split execution rewards with the pool
     */
    uint256 internal _executionCommission;

    /**
     * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     */
    uint256 internal _protocolFeeRate;

    /**
     * @dev Deposit rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     */
    uint256 internal _depositRate;

    /**
     * @dev Puffer finance treasury
     */
    address internal _treasury;

    /**
     * @dev Validator bond for non custodial node runners
     */
    uint256 internal _nonCustodialBondRequirement;

    /**
     * @dev Validator bond for non enclave node runners
     */
    uint256 internal _nonEnclaveBondRequirement;

    /**
     * @dev Validator bond for Enclave node runners
     */
    uint256 internal _enclaveBondRequirement;

    /**
     * @dev Withdrawal pool address
     */
    address internal _withdrawalPool;

    /**
     * @dev Guardian {Safe} Module
     */
    GuardianModule internal _guardianModule;

    /**
     * @dev EigenLayer's Strategy Manager
     */
    IStrategyManager internal _strategyManager;

    /**
     * @dev Enclave verifier smart contract
     */
    IEnclaveVerifier internal _enclaveVerifier;

    /**
     * @dev Public keys of the active validators
     */
    EnumerableSet.Bytes32Set internal _pubKeyHashes;

    /**
     * @dev This function is not requesting a msg.sender to be a {Safe} multisig.
     *     Instead it will allow a call from one of the {Safe} Pod account owners to be authorized
     *     So if Pod account is owned by 5 owners, any of them sending a request for that podAccount will be authorized
     */
    modifier onlyPodAccountOwner(IEigenPodProxy eigenPodProxy) {
        _onlyPodAccountOwner(eigenPodProxy);
        _;
    }

    /**
     * @dev Allow a call from guardians multisig
     */
    modifier onlyGuardians() {
        _onlyGuardians();
        _;
    }

    modifier onlyPodProxy() {
        // Ensure caller corresponds to an instantiated PodPoxy contract
        if (_eigenPodProxies[msg.sender].creator == address(0)) {
            revert Unauthorized();
        }
        _;
    }

    constructor(address beacon) {
        EIGEN_POD_PROXY_BEACON = beacon;
        EIGEN_POD_MANAGER = IEigenPodProxy(UpgradeableBeacon((beacon)).implementation()).getEigenPodManager();
        _disableInitializers();
    }

    receive() external payable {
        _splitETH(true);
    }

    function _splitETH(bool includeProtocolFee) internal {
        uint256 protocolFee;

        if (includeProtocolFee) {
            // Calculate and split between the treasury, deposit pool and the withdrawal pool
            protocolFee = FixedPointMathLib.fullMulDiv(msg.value, _protocolFeeRate, _ONE_HUNDRED_WAD);
            SafeTransferLib.safeTransferETH(_treasury, protocolFee);
        }

        // PufferPool is the deposit pool, so we just leave this amount in this contract
        uint256 depositPoolAmount =
            FixedPointMathLib.fullMulDiv((msg.value - protocolFee), _depositRate, _ONE_HUNDRED_WAD);

        // We transfer this amount to Withdrawal Pool contract
        uint256 withdrawalPoolAmount = msg.value - protocolFee - depositPoolAmount;
        SafeTransferLib.safeTransferETH(_withdrawalPool, withdrawalPoolAmount);
    }

    function initialize(
        address safeProxyFactory,
        address safeImplementation,
        address[] calldata treasuryOwners,
        address withdrawalPool,
        address guardianSafeModule,
        address enclaveVerifier,
        bytes calldata data
    ) external initializer {
        __ReentrancyGuard_init(); // TODO: figure out if really need it?
        __UUPSUpgradeable_init();
        __ERC20_init("Puffer ETH", "pufETH");
        __Pausable_init();
        __Ownable_init();
        _setSafeProxyFactory(safeProxyFactory);
        _setSafeImplementation(safeImplementation);
        _setEnclaveVerifier(enclaveVerifier);
        _setNonCustodialBondRequirement(16 ether);
        _setNonEnclaveBondRequirement(8 ether);
        _setEnclaveBondRequirement(2 ether);

        address treasury = address(
            _deploySafe({
                safeProxyFactory: _safeProxyFactory,
                safeSingleton: _safeImplementation,
                saltNonce: uint256(keccak256("treasury")),
                owners: treasuryOwners,
                threshold: treasuryOwners.length,
                to: address(0),
                data: data
            })
        );

        _guardianModule = GuardianModule(guardianSafeModule);
        _setTreasury(treasury);
        _setDepositRate(90 * FixedPointMathLib.WAD); // 90%
        _setProtocolFeeRate(5 * FixedPointMathLib.WAD); // 5%

        // TODO: use constants / immutables
        _withdrawalPool = withdrawalPool;
    }

    // Guardians only

    function updateETHBackingAmount(uint256 amount) external onlyGuardians { }

    /**
     * @inheritdoc IPufferPool
     */
    function provisionPodETH(
        address eigenPodProxy,
        bytes calldata pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external {
        bytes32 pubKeyHash = keccak256(pubKey);

        // Make sure that the validator is in the correct status
        if (
            _eigenPodProxies[address(eigenPodProxy)].validatorInformation[pubKeyHash].status
                != IPufferPool.Status.PENDING
        ) {
            revert InvalidBLSPubKey();
        }

        // Validate guardian signatures
        _validateGuardianSignatures(eigenPodProxy, pubKey, guardianEnclaveSignatures);

        // Update Validator status
        _eigenPodProxies[eigenPodProxy].validatorInformation[pubKeyHash].status = IPufferPool.Status.VALIDATING;

        // Update locked ETH Amount
        _lockedETHAmount += _32_ETHER;

        // TODO: params
        EigenPodProxy(payable(eigenPodProxy)).callStake{ value: _32_ETHER }({
            pubKey: pubKey,
            signature: signature,
            depositDataRoot: depositDataRoot
        });

        // TODO: event update
        emit ETHProvisioned(eigenPodProxy, pubKey, block.timestamp);
    }

    function _validateGuardianSignatures(
        address eigenPodProxy,
        bytes calldata pubKey,
        bytes[] calldata guardianEnclaveSignatures
    ) internal view {
        address lastSigner = address(0);
        address currentSigner;

        // Get guardian enclave addresses
        address[] memory enclaveAddresses = _guardianModule.getGuardiansEnclaveAddresses(_guardiansMultisig);

        // create a hash // TODO: use EIP712?, or go with the simple version like this?
        bytes32 msgToBeSigned = keccak256(abi.encodePacked(eigenPodProxy, pubKey)).toEthSignedMessageHash();

        uint256 validSignatures;

        // Iterate through guardian enclave addresses and make sure that the signers match
        for (uint256 i = 0; i < enclaveAddresses.length;) {
            currentSigner = ECDSA.recover(msgToBeSigned, guardianEnclaveSignatures[i]);
            if (currentSigner == address(0)) {
                revert Unauthorized();
            }
            // Signatures need to be sorted in ascending order based on signer addresses
            if (currentSigner <= lastSigner) {
                revert Unauthorized();
            }
            for (uint256 j = 0; j < enclaveAddresses.length;) {
                if (enclaveAddresses[j] == currentSigner) {
                    lastSigner = currentSigner;
                    validSignatures++;
                    break;
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        if (validSignatures < _guardiansMultisig.getThreshold()) {
            revert Unauthorized();
        }
    }

    /**
     * @inheritdoc IPufferPool
     */
    function depositETH(address recipient) external payable whenNotPaused {
        if (msg.value < _MINIMUM_DEPOSIT_AMOUNT) {
            revert InsufficientETH();
        }

        uint256 pufETHAmount = calculateETHToPufETHAmount(msg.value);

        _mint(recipient, pufETHAmount);

        emit Deposited(msg.sender, recipient, msg.value, pufETHAmount);

        _splitETH(false);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function burn(uint256 pufETHAmount) external whenNotPaused {
        _burn(msg.sender, pufETHAmount);
    }

    /**
     * Distributes all ETH to the pool and PodProxyOwner upon protocol exit
     */
    function withdrawFromProtocol(uint256 pufETHAmount, address podRewardsRecipient) external payable onlyPodProxy {
        // convert pufETH to ETH
        uint256 ethAmount = calculatePufETHtoETHAmount(pufETHAmount);

        // Burn pufETH on the sender's account
        _burn(msg.sender, pufETHAmount);

        // Payout the validator
        int256 toTransfer = int256(msg.value) - int256(32 ether);

        if (toTransfer >= 0) {
            // Return bond and any rewards back to podRewardsRecipient
            SafeTransferLib.safeTransferETH(podRewardsRecipient, uint256(toTransfer));
        }

        // TODO: tax?
        _splitETH(false);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createGuardianAccount(address[] calldata guardiansWallets, uint256 threshold, bytes calldata data)
        external
        returns (Safe account)
    {
        if (address(_guardiansMultisig) != address(0)) {
            revert GuardiansAlreadyExist();
        }

        // Deploy {Safe} and enable module
        account = _deploySafe({
            safeProxyFactory: _safeProxyFactory,
            safeSingleton: _safeImplementation,
            saltNonce: uint256(keccak256(abi.encode(guardiansWallets))),
            owners: guardiansWallets,
            threshold: threshold,
            to: address(_guardianModule),
            data: data
        });

        _guardiansMultisig = account;

        emit GuardianAccountCreated(address(account));
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createPodAccount(
        address[] calldata podAccountOwners,
        uint256 threshold,
        address podRewardsRecipient,
        bytes calldata data
    ) external returns (Safe, IEigenPodProxy) {
        return _createPodAccountAndEigenPodProxy(podAccountOwners, threshold, podRewardsRecipient, data);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createPodAccountAndRegisterValidatorKey(
        address[] calldata podAccountOwners,
        uint256 podAccountThreshold,
        ValidatorKeyData calldata data,
        address podRewardsRecipient,
        bytes calldata podData
    ) external payable whenNotPaused returns (Safe, IEigenPodProxy) {
        (Safe account, IEigenPodProxy eigenPodProxy) =
            _createPodAccountAndEigenPodProxy(podAccountOwners, podAccountThreshold, podRewardsRecipient, podData);
        registerValidatorKey(eigenPodProxy, data);
        return (account, eigenPodProxy);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getEigenPodProxyAndEigenPod(address creator) public view returns (address, address) {
        bytes memory bytecode = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(EIGEN_POD_PROXY_BEACON, abi.encodeCall(EigenPodProxy.initialize, (this)))
        );

        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), keccak256(abi.encodePacked(creator)), keccak256(bytecode))
        );

        address eigenPodProxy = address(uint160(uint256(hash)));

        address eigenPod = address(IEigenPodManager(EIGEN_POD_MANAGER).getPod(eigenPodProxy));

        return (eigenPodProxy, eigenPod);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function registerValidatorKey(IEigenPodProxy eigenPodProxy, ValidatorKeyData calldata data)
        public
        payable
        onlyPodAccountOwner(eigenPodProxy)
        whenNotPaused
    {
        // Sanity check on blsPubKey
        if (data.blsPubKey.length != 48) {
            revert InvalidBLSPubKey();
        }

        bytes32 pubKeyHash = keccak256(data.blsPubKey);

        // Make sure that there are no duplicate keys
        bool added = _pubKeyHashes.add(pubKeyHash);
        if (!added) {
            revert PublicKeyIsAlreadyActive();
        }

        uint256 validatorBondRequirement = _getValidatorBondRequirement(data.evidence, data.blsEncPrivKeyShares);
        if (msg.value != validatorBondRequirement) {
            revert InvalidAmount();
        }

        _validateCustody(data);

        uint256 pufETHBondAmount = calculateETHToPufETHAmount(msg.value);

        // Mint pufETH to validator and lock it there
        _mint(address(eigenPodProxy), pufETHBondAmount);

        // Save information
        _eigenPodProxies[address(eigenPodProxy)].validatorInformation[pubKeyHash] =
            IPufferPool.ValidatorInfo({ bond: pufETHBondAmount, status: IPufferPool.Status.PENDING });

        emit ValidatorKeyRegistered(address(eigenPodProxy), data.blsPubKey);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function stopRegistration(bytes32 publicKeyHash) external {
        // `msg.sender` is EigenPodProxy
        IPufferPool.ValidatorInfo storage info = _eigenPodProxies[msg.sender].validatorInformation[publicKeyHash];

        if (info.status != IPufferPool.Status.PENDING) {
            revert InvalidValidatorStatus();
        }

        uint256 bond = info.bond;
        // Remove Bond amount and updte status
        info.bond = 0;
        info.status = IPufferPool.Status.BOND_WITHDRAWN;

        // Trigger the pufETH transfer
        IEigenPodProxy(msg.sender).releaseBond(bond);
    }

    function setNewRewardsETHAmount(uint256 amount) external {
        // TODO: everything
        _newETHRewardsAmount = amount;
    }

    // ==== Only Owner ====

    /**
     * @inheritdoc IPufferOwner
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function resume() external onlyOwner {
        _unpause();
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function changeAVSConfiguration(address avs, AVSParams memory configuration) external onlyOwner {
        _allowedAVSs[avs] = configuration;
        emit AVSConfigurationChanged(avs, configuration);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function changeSafeImplementation(address newSafeImplementation) external onlyOwner {
        _setSafeImplementation(newSafeImplementation);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function changeSafeProxyFactory(address newSafeFactory) external onlyOwner {
        _setSafeProxyFactory(newSafeFactory);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function setExecutionCommission(uint256 newValue) external onlyOwner {
        _setExecutionCommission(newValue);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function changeTreasury(address treasury) external onlyOwner {
        _setTreasury(treasury);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function setConsensusCommission(uint256 newValue) external onlyOwner {
        _setConsensusCommission(newValue);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function setAvsCommission(uint256 newValue) external onlyOwner {
        _setAvsCommission(newValue);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function setNodeEnclaveMeasurements(bytes32 mrenclave, bytes32 mrsigner) external onlyOwner { }

    /**
     * @inheritdoc IPufferOwner
     */
    function setGuardianEnclaveMeasurements(bytes32 mrenclave, bytes32 mrsigner) external onlyOwner { }

    // TODO: do we really need this? use constants?
    function setNonCustodialBondRequirement(uint256 newValue) external onlyOwner {
        _setNonCustodialBondRequirement(newValue);
    }

    function setNonEnclaveBondRequirement(uint256 newValue) external onlyOwner {
        _setNonEnclaveBondRequirement(newValue);
    }

    function setEnclaveBondRequirement(uint256 newValue) external onlyOwner {
        _setEnclaveBondRequirement(newValue);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function setProtocolFeeRate(uint256 protocolFeeRate) external onlyOwner {
        _setProtocolFeeRate(protocolFeeRate);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function setDepositRate(uint256 depositRate) external onlyOwner {
        _setDepositRate(depositRate);
    }

    // ==== Only Owner end ====

    function getGuardianModule() external view returns (GuardianModule) {
        return _guardianModule;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function calculateETHToPufETHAmount(uint256 amount) public view returns (uint256) {
        return FixedPointMathLib.divWad(amount, _getPufETHtoETHExchangeRate(amount));
    }

    /**
     * @inheritdoc IPufferPool
     */
    function calculatePufETHtoETHAmount(uint256 pufETHAmount) public view returns (uint256) {
        return FixedPointMathLib.mulWad(pufETHAmount, getPufETHtoETHExchangeRate());
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getLockedETHAmount() public view returns (uint256) {
        return _lockedETHAmount;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getTreasury() public view returns (address) {
        return _treasury;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getValidatorInfo(address eigenPodProxy, bytes32 pubKeyHash) external view returns (ValidatorInfo memory) {
        return _eigenPodProxies[eigenPodProxy].validatorInformation[pubKeyHash];
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getNewRewardsETHAmount() public view returns (uint256) {
        return _newETHRewardsAmount;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getExecutionCommission() external view returns (uint256) {
        return _executionCommission;
    }

    function getExecutionAmount(uint256 amount) external view returns (uint256) {
        return FixedPointMathLib.fullMulDiv(amount, _executionCommission, _ONE_HUNDRED_WAD);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getNodeEnclaveMeasurements() external returns (bytes32 mrenclave, bytes32 mrsigner) { }

    /**
     * @inheritdoc IPufferPool
     */
    function getGuardianEnclaveMeasurements() external returns (bytes32 mrenclave, bytes32 mrsigner) { }

    /**
     * @inheritdoc IPufferPool
     */
    function getConsensusCommission() external view returns (uint256) {
        return _consensusCommission;
    }

    function getDepositRate() external view returns (uint256) {
        return _depositRate;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function isAVSEnabled(address avs) public view returns (bool) {
        return _allowedAVSs[avs].enabled;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getAVSComission(address avs) public view returns (uint256) {
        return _allowedAVSs[avs].podAVSCommission;
    }

    // TODO: Will remove and replace this with above function
    function getAvsCommission() public view returns (uint256) {
        return _avsCommission;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getMinBondRequirement(address avs) external view returns (uint256) {
        return uint256(_allowedAVSs[avs].minBondRequirement);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getPufETHtoETHExchangeRate() public view returns (uint256) {
        return _getPufETHtoETHExchangeRate(0);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getSafeImplementation() external view returns (address) {
        return _safeImplementation;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getSafeProxyFactory() external view returns (address) {
        return _safeProxyFactory;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getPufferAvsAddress() external view returns (address) {
        return _pufferAvsAddress;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getBeaconChainETHStrategyIndex() external pure returns (uint256) {
        return _beaconChainETHStrategyIndex;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getBeaconChainETHStrategy() external pure returns (IStrategy) {
        return _beaconChainETHStrategy;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getStrategyManager() external view returns (IStrategyManager) {
        return _strategyManager;
    }

    function _getPufETHtoETHExchangeRate(uint256 ethDepositedAmount) internal view returns (uint256) {
        uint256 pufETHSupply = totalSupply();
        if (pufETHSupply == 0) {
            return FixedPointMathLib.WAD;
        }
        // address(this).balance - ethDepositedAmount is actually balance of this contract before the deposit
        uint256 exchangeRate = FixedPointMathLib.divWad(
            getLockedETHAmount() + getNewRewardsETHAmount() + address(_withdrawalPool).balance
                + (address(this).balance - ethDepositedAmount),
            pufETHSupply
        );

        return exchangeRate;
    }

    // TODO: timelock on upgrade?
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner { }

    /**
     * @dev Creates eigen pod proxy via create2
     */
    function _createEigenPodProxy(address msgSender) internal returns (IEigenPodProxy eigenPodProxy) {
        bytes memory deploymentData = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(EIGEN_POD_PROXY_BEACON, abi.encodeCall(EigenPodProxy.initialize, (this)))
        );

        // Convert address to addressHash for salt
        bytes32 addressHash = keccak256(abi.encodePacked(msgSender));

        // solhint-disable-next-line no-inline-assembly
        assembly {
            eigenPodProxy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), addressHash)
        }

        if (address(eigenPodProxy) == address(0)) {
            revert Create2Failed();
        }

        // Save EigenPodProxy Information
        _eigenPodProxies[address(eigenPodProxy)].creator = msg.sender;

        return IEigenPodProxy(address(eigenPodProxy));
    }

    function _createPodAccountAndEigenPodProxy(
        address[] calldata podAccountOwners,
        uint256 threshold,
        address podRewardsRecipient,
        bytes calldata data
    ) internal returns (Safe, IEigenPodProxy) {
        Safe account = _deploySafe({
            safeProxyFactory: _safeProxyFactory,
            safeSingleton: _safeImplementation,
            saltNonce: block.timestamp, // TODO: change
            owners: podAccountOwners,
            threshold: threshold,
            to: address(0),
            data: data
        });

        // msg.sender is caller of the `createPodAccount` or `createPodAccountAndRegisterValidatorKey`
        IEigenPodProxy eigenPodProxy = _createEigenPodProxy(msg.sender);

        _eigenPodProxies[address(eigenPodProxy)].creator = msg.sender;

        eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(payable(address(account)), payable(podRewardsRecipient));

        emit PodAccountAndEigenPodProxyCreated(msg.sender, address(account), address(eigenPodProxy));

        return (account, eigenPodProxy);
    }

    function _validateCustody(ValidatorKeyData calldata data) internal view {
        if (data.evidence.report.length + data.blsEncPrivKeyShares.length == 0) {
            // First case:
            // No enclave or guardian custody
            // We don't do validations
            return;
        }

        // Second case + Third case validations
        // We validate that the number of key shares match number of guardians

        uint256 nubmerOfGuardians = _guardiansMultisig.getOwners().length;
        if (data.blsEncPrivKeyShares.length != nubmerOfGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeyShares.length != nubmerOfGuardians) {
            revert InvalidBLSPublicKeyShares();
        }

        if (data.evidence.report.length == 0) {
            // Second case:
            // No Enclave but gives custody
            return;
        }

        // Third case:
        // Enclave and gives custody
        // Do RAVE validation
        bool custodyVerified = _enclaveVerifier.verifyValidatorPubKey({
            pubKey: data.blsPubKey,
            blockNumber: data.blockNumber,
            evidence: data.evidence,
            mrenclave: data.mrenclave,
            mrsigner: data.mrsigner
        });

        if (!custodyVerified) {
            revert CouldNotVerifyCustody();
        }
    }

    function _setSafeProxyFactory(address safeProxyFactory) internal {
        _safeProxyFactory = safeProxyFactory;
        emit SafeProxyFactoryChanged(safeProxyFactory);
    }

    function _setSafeImplementation(address safeImplementation) internal {
        _safeImplementation = safeImplementation;
        emit SafeImplementationChanged(safeImplementation);
    }

    function _setEnclaveVerifier(address enclaveVerifier) internal {
        _enclaveVerifier = IEnclaveVerifier(enclaveVerifier);
        emit EnclaveVerifierChanged(enclaveVerifier);
    }

    function _setExecutionCommission(uint256 newValue) internal {
        uint256 oldValue = _executionCommission;
        _executionCommission = newValue;
        emit ExecutionCommissionChanged(oldValue, newValue);
    }

    function _setConsensusCommission(uint256 newValue) internal {
        uint256 oldValue = _consensusCommission;
        _consensusCommission = newValue;
        emit ConsensusCommissionChanged(oldValue, newValue);
    }

    function _setAvsCommission(uint256 newValue) internal {
        uint256 oldValue = _avsCommission;
        _avsCommission = newValue;
        emit AvsCommissionChanged(oldValue, newValue);
    }

    function _setNonCustodialBondRequirement(uint256 newValue) internal {
        uint256 oldValue = _avsCommission;
        _nonCustodialBondRequirement = newValue;
        emit NonCustodialBondRequirementChanged(oldValue, newValue);
    }

    function _setNonEnclaveBondRequirement(uint256 newValue) internal {
        uint256 oldValue = _avsCommission;
        _nonEnclaveBondRequirement = newValue;
        emit NonEnclaveBondRequirementChanged(oldValue, newValue);
    }

    function _setEnclaveBondRequirement(uint256 newValue) internal {
        uint256 oldValue = _avsCommission;
        _enclaveBondRequirement = newValue;
        emit EnclaveBondRequirementChanged(oldValue, newValue);
    }

    function _setTreasury(address treasury) internal {
        address oldTreasury = _treasury;
        _treasury = treasury;
        emit TreasuryChanged(oldTreasury, treasury);
    }

    function _setProtocolFeeRate(uint256 protocolFee) internal {
        uint256 oldProtocolFee = _protocolFeeRate;
        _protocolFeeRate = protocolFee;
        emit ProtocolFeeRateChanged(oldProtocolFee, protocolFee);
    }

    function _setDepositRate(uint256 depositRate) internal {
        uint256 oldDepositRate = _depositRate;
        _depositRate = depositRate;
        emit DepositRateChanged(oldDepositRate, depositRate);
    }

    function _getValidatorBondRequirement(RaveEvidence calldata raveEvidence, bytes[] calldata blsEncPrivKeyShares)
        internal
        view
        returns (uint256)
    {
        if (raveEvidence.report.length + blsEncPrivKeyShares.length == 0) {
            return _nonCustodialBondRequirement;
        }

        if (raveEvidence.report.length == 0) {
            return _nonEnclaveBondRequirement;
        }

        return _enclaveBondRequirement;
    }

    function _onlyGuardians() internal view {
        if (msg.sender != address(_guardiansMultisig)) {
            revert Unauthorized();
        }
    }

    /**
     * @param eigenPodProxy is the EigenPodProxy address
     */
    function _onlyPodAccountOwner(IEigenPodProxy eigenPodProxy) internal view {
        Safe podAccount = Safe(payable(eigenPodProxy.getPodProxyOwner()));
        if (!podAccount.isOwner(msg.sender)) {
            revert Unauthorized();
        }
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
