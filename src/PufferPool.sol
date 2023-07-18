// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20PermitUpgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "openzeppelin-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { OwnableUpgradeable } from "openzeppelin-upgradeable/access/OwnableUpgradeable.sol";
import { PausableUpgradeable } from "openzeppelin-upgradeable/security/PausableUpgradeable.sol";
import { SafeDeployer } from "puffer/SafeDeployer.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";

/**
 * @title PufferPool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 * @notice
 */
contract PufferPool is
    IPufferPool,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    ERC20PermitUpgradeable,
    SafeDeployer
{
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /**
     * @notice Validator bond in Puffer Finance is 2 ETH
     */
    uint256 internal constant _VALIDATOR_BOND = 2 ether;

    /**
     * @notice ETH Amount That Puffer is supplying to Validator
     */
    uint256 internal constant _THIRTY_ETHER = 30 ether;

    /**
     * @notice Exchange rate 1 is represented as 10 ** 18
     */
    uint256 internal constant _ONE = 10 ** 18;

    /**
     * @notice Minimum deposit amount in ETH
     */
    uint256 internal constant _MINIMUM_DEPOSIT_AMOUNT = 0.01 ether;

    /**
     * @notice Address of the Eigen pod proxy beacon
     */
    address public immutable EIGEN_POD_PROXY_BEACON;

    /**
     * @notice Locked ETH amount
     */
    uint256 _lockedETHAmount;

    /**
     * @notice New rewards amount
     */
    uint256 _newETHRewardsAmount;

    /**
     * @dev Guardians multisig wallet
     */
    Safe internal _guardiansMultisig;

    /**
     * @dev EigenPodProxy -> EigenPodProxyInformation
     */
    mapping(address eigenPodProxy => EigenPodProxyInformation info) internal _eigenPodProxies;

    /**
     * @dev Address of the {Safe} proxy factory
     */
    address internal _safeProxyFactory;

    /**
     * @dev Address of the {Safe} implementation contract
     */
    address internal _safeImplementation;

    /**
     * @dev Maximum number of Validators per EigenPodProxy
     */
    uint8 internal _eigenPodValidatorLimit;

    modifier onlyPod() {
        // TODO logic:
        _;
    }

    modifier onlyGuardians() {
        if (msg.sender != address(_guardiansMultisig)) {
            revert Unauthorized();
        }
        _;
    }

    constructor(address beacon) {
        EIGEN_POD_PROXY_BEACON = beacon;
        _disableInitializers();
    }

    receive() external payable { }

    function initialize(address safeProxyFactory, address safeImplementation) external initializer {
        __ReentrancyGuard_init(); // TODO: figure out if really need it?
        __UUPSUpgradeable_init();
        __ERC20_init("Puffer ETH", "pufETH");
        __Pausable_init();
        __Ownable_init();
        _setSafeProxyFactory(safeProxyFactory);
        _setSafeImplementation(safeImplementation);
        _setEigenPodValidatorLimit(1);
    }

    // Guardians only

    /**
     * @inheritdoc IPufferPool
     */
    function ejectValidator() external onlyGuardians { }

    function updateETHBackingAmount(uint256 amount) external onlyGuardians { }

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
    }

    /**
     * @inheritdoc IPufferPool
     */
    function withdrawETH(address ethRecipient, uint256 pufETHAmount) external whenNotPaused {
        uint256 ethAmount = calculatePufETHtoETHAmount(pufETHAmount);

        _burn(msg.sender, pufETHAmount);

        _safeTransferETH(ethRecipient, ethAmount);

        emit Withdrawn(msg.sender, ethRecipient, pufETHAmount, ethAmount);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function provisionPodETH(
        address eigenPodProxy,
        bytes calldata pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external onlyGuardians {
        // TODO: validations
        // if ()

        // TODO: mint pufETH to Validator?

        EigenPodProxyInformation storage validatorInfo = _eigenPodProxies[eigenPodProxy];

        // Validate pubKey matches

        if (validatorInfo.validatorPubKeyHashes.contains(keccak256(pubKey))) {
            revert();
        }

        uint256 validatorIdx;

        // Update locked ETH Amount
        _lockedETHAmount += _THIRTY_ETHER;

        // TODO: params
        EigenPodProxy(payable(eigenPodProxy)).callStake{ value: _THIRTY_ETHER }({
            pubKey: pubKey,
            signature: signature,
            depositDataRoot: depositDataRoot
        });

        emit ETHProvisioned(eigenPodProxy, validatorIdx, block.timestamp);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createGuardianAccount(
        bytes[] calldata guardiansEnclavePubKeys,
        address[] calldata guardiansWallets,
        uint256 threshold,
        bytes32 mrenclave
    ) external returns (Safe account) {
        if (address(_guardiansMultisig) != address(0)) {
            revert GuardiansAlreadyExist();
        }

        account = _deploySafe({
            safeProxyFactory: _safeProxyFactory,
            safeSingleton: _safeImplementation,
            saltNonce: uint256(mrenclave),
            owners: guardiansWallets,
            threshold: threshold
        });

        _guardiansMultisig = account;

        emit GuardianAccountCreated(mrenclave, address(account));
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createPodAccount(address[] calldata podAccountOwners, uint256 threshold)
        external
        returns (Safe, IEigenPodProxy)
    {
        return _createPodAccount(podAccountOwners, threshold);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createPodAccountAndRegisterValidatorKeys(
        address[] calldata podAccountOwners,
        uint256 threshold,
        bytes[] calldata pubKeys
    ) external payable returns (Safe, IEigenPodProxy) {
        (Safe account, IEigenPodProxy eigenPodProxy) = _createPodAccount(podAccountOwners, threshold);
        _registerValidatorEnclaveKeys(address(eigenPodProxy), pubKeys);
        return (account, eigenPodProxy);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function registerValidatorEnclaveKeys(address eigenPodProxy, bytes[] calldata pubKeys) external payable {
        _registerValidatorEnclaveKeys(eigenPodProxy, pubKeys);
    }

    function _createPodAccount(address[] calldata podAccountOwners, uint256 threshold)
        internal
        returns (Safe, IEigenPodProxy)
    {
        Safe account = _deploySafe({
            safeProxyFactory: _safeProxyFactory,
            safeSingleton: _safeImplementation,
            saltNonce: block.timestamp,
            owners: podAccountOwners,
            threshold: threshold
        });

        // Forward bond amount to newly deployed Eigen Pod Proxy
        // It will sit there untill Guardians alocate the rest
        BeaconProxy eigenPodProxy =
        new BeaconProxy(EIGEN_POD_PROXY_BEACON, abi.encodeCall(EigenPodProxy.initialize, (address(account), address(this))));

        // Save information
        _eigenPodProxies[address(eigenPodProxy)].creator = msg.sender;

        emit PodAccountCreated(msg.sender, address(account), address(eigenPodProxy));

        return (account, IEigenPodProxy(address(eigenPodProxy)));
    }

    function _registerValidatorEnclaveKeys(address eigenPodProxy, bytes[] calldata pubKeys) internal {
        if (msg.value != pubKeys.length * _VALIDATOR_BOND) {
            revert InsufficientETH();
        }

        // TODO: this will allow anybody to register a validator pubKey to a certain eigenPodProxy as long as it pays the bond
        // This might not be the behaviour we want
        // what other checks do we want here? only allow EigenPodOwners to do that?

        EigenPodProxyInformation storage info = _eigenPodProxies[eigenPodProxy];

        if ((info.validatorPubKeyHashes.length() + pubKeys.length) > _eigenPodValidatorLimit) {
            revert MaximumNumberOfValidatorsReached();
        }

        // If the EigenPodProxy doesn't have a creator, that means that it is not a valid address
        if (info.creator == address(0)) {
            revert InvalidEigenPodProxy();
        }

        for (uint256 i; i < pubKeys.length;) {
            bool keyAdded = info.validatorPubKeyHashes.add(keccak256(pubKeys[i]));

            if (!keyAdded) {
                // TODO: should we check that the 1 validator key must be registered to 1 pod?
                revert DuplicateValidatorKey(pubKeys[i]);
            }

            emit ValidatorKeyRegistered(eigenPodProxy, pubKeys[i]);

            unchecked {
                ++i;
            }
        }

        // Transfer ETH to EigenPodProxy
        _safeTransferETH(eigenPodProxy, msg.value);
    }

    function setNewRewardsETHAmount(uint256 amount) external {
        // TODO: everything
        _newETHRewardsAmount = amount;
    }

    // ==== Only Owner ====

    /**
     * @inheritdoc IPufferPool
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @inheritdoc IPufferPool
     */
    function resume() external onlyOwner {
        _unpause();
    }

    /**
     * @inheritdoc IPufferPool
     */
    function changeSafeImplementation(address newSafeImplementation) external onlyOwner {
        _setSafeImplementation(newSafeImplementation);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function changeSafeProxyFactory(address newSafeFactory) external onlyOwner {
        _setSafeProxyFactory(newSafeFactory);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function changeEigenPodValidatorLimit(uint256 newLimit) external onlyOwner {
        _setEigenPodValidatorLimit(newLimit);
    }

    // ==== Only Owner end ====

    /**
     * @inheritdoc IPufferPool
     */
    function calculateETHToPufETHAmount(uint256 amount) public view returns (uint256) {
        return amount * _ONE / _getPufETHtoETHExchangeRate(amount);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function calculatePufETHtoETHAmount(uint256 pufETHAmount) public view returns (uint256) {
        return pufETHAmount * getPufETHtoETHExchangeRate() / _ONE;
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
    function getNewRewardsETHAmount() public view returns (uint256) {
        return _newETHRewardsAmount;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getEigenPodValidatorLimit() external view returns (uint256) {
        return _eigenPodValidatorLimit;
    }

    // /**
    //  * @inheritdoc IPufferPool
    //  */
    // function getEigenPodProxyInfo(address eigenPodProxy) public view returns (EigenPodProxyInformation memory) {
    //     return _eigenPodProxies[eigenPodProxy];
    // }

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

    function _getPufETHtoETHExchangeRate(uint256 ethDepositedAmount) internal view returns (uint256) {
        uint256 pufETHSupply = totalSupply();
        if (pufETHSupply == 0) {
            return _ONE;
        }
        // address(this).balance - ethDepositedAmount is actually balance of this contract before the deposit
        uint256 exchangeRate = (
            getLockedETHAmount() + getNewRewardsETHAmount() + address(this).balance - ethDepositedAmount
        ) * _ONE / pufETHSupply;

        return exchangeRate;
    }

    // TODO: timelock on upgrade?
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner { }

    /**
     * @dev Helper function for transfering ETH
     * https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol
     */
    function _safeTransferETH(address to, uint256 amount) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // Transfer the ETH and store if it succeeded or not.
            success := call(gas(), to, amount, 0, 0, 0, 0)
        }

        require(success);
    }

    function _setSafeProxyFactory(address safeProxyFactory) internal {
        _safeProxyFactory = safeProxyFactory;
        emit SafeProxyFactoryChanged(safeProxyFactory);
    }

    function _setSafeImplementation(address safeImplementation) internal {
        _safeImplementation = safeImplementation;
        emit SafeImplementationChanged(safeImplementation);
    }

    function _setEigenPodValidatorLimit(uint256 newLimit) internal {
        _eigenPodValidatorLimit = uint8(newLimit);
        emit EigenPodValidatorLimitChanged(newLimit);
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
