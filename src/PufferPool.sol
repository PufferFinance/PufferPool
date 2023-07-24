// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20PermitUpgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "openzeppelin-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { SignedMath } from "openzeppelin/utils/math/SignedMath.sol";
import { OwnableUpgradeable } from "openzeppelin-upgradeable/access/OwnableUpgradeable.sol";
import { PausableUpgradeable } from "openzeppelin-upgradeable/security/PausableUpgradeable.sol";
import { SafeDeployer } from "puffer/SafeDeployer.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IPufferOwner } from "puffer/interface/IPufferOwner.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";

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
    /**
     * @notice ETH Amount required for becoming a Validator
     */
    uint256 internal constant _32_ETHER = 32 ether;

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
    uint256 internal _lockedETHAmount;

    /**
     * @notice New rewards amount
     */
    uint256 internal _newETHRewardsAmount;

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

    // TODO: Getters and Setters
    /**
     *
     * @dev Address of the treasury pool
     */
    address internal _treasury;

    /**
     * @dev Address of the {Safe} implementation contract
     */
    address internal _safeImplementation;

    /**
     * @dev Number of shares out of one billion to split AVS rewards with the pool
     */
    uint256 internal _avsCommission;

    /**
     * Number of shares out of one billion to split consensus rewards with the pool
     */
    uint256 internal _consensusCommission;

    /**
     * Number of shares out of one billion to split execution rewards with the pool
     */
    uint256 internal _executionCommission;

    /**
     *
     * Number of shares out of one billion to split pool rewards with the treasury
     */
    uint256 internal _treasuryCommission;

    /**
     * The denomination of shares represented by each commission value (e.g. one billion)
     */
    uint256 internal _commissionDenominator;

    /**
     * @notice Validator bond for non custodial node runners
     */
    uint256 internal _nonCustodialBondRequirement;

    /**
     * @notice Validator bond for non enclave node runners
     */
    uint256 internal _nonEnclaveBondRequirement;

    /**
     * @notice Validator bond for Enclave node runners
     */
    uint256 internal _enclaveBondRequirement;

    modifier onlyPodAccountOwner(address podAccount) {
        if (!Safe(payable(podAccount)).isOwner(msg.sender)) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyGuardians() {
        if (msg.sender != address(_guardiansMultisig)) {
            revert Unauthorized();
        }
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
        _setNonCustodialBondRequirement(16 ether);
        _setNonEnclaveBondRequirement(8 ether);
        _setEnclaveBondRequirement(2 ether);
    }

    // Guardians only

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
        // TODO: logic for this

        // Update locked ETH Amount
        _lockedETHAmount += _32_ETHER;

        // TODO: params
        EigenPodProxy(payable(eigenPodProxy)).callStake{ value: _32_ETHER }(pubKey, signature, depositDataRoot);

        // TODO: event update
        emit ETHProvisioned(eigenPodProxy, 0, block.timestamp);
    }

    /**
     * Distributes all ETH to the pool and PodProxyOwner upon protocol exit
     */
    function withdrawFromProtocol(
        uint256 pufETHAmount,
        uint256 skimmable,
        uint256 withdrawnETH,
        address podRewardsRecipient,
        uint256 bondAmount
    ) external payable onlyPodProxy {
        // Burn all pufETH on the sender's account
        _burn(msg.sender, pufETHAmount);

        // BondFinal should be the value of the bond, taking into account the exchange rate of pufETH and ETH
        uint256 bondFinal = calculatePufETHtoETHAmount(pufETHAmount);
        int256 debt = int256(32 ether - int256(bondFinal)) - int256(withdrawnETH);

        if (debt <= 0) {
            // ETH owed to podProxyOwner
            uint256 podRewards = (skimmable * _consensusCommission) / _commissionDenominator;

            // Distribute pool rewards to the treasury
            uint256 poolRewards = skimmable - podRewards;
            _safeTransferETH(_treasury, (poolRewards * _treasuryCommission) / _commissionDenominator);

            // Return up to 2 ETH bond and rewards back to podRewardsRecipient
            _safeTransferETH(
                podRewardsRecipient,
                SignedMath.abs(
                    SignedMath.max(
                        (int256(withdrawnETH) - int256(32 ether - int256(bondFinal))) + int256(podRewards), 0
                    )
                )
            );
        }
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createGuardianAccount(address[] calldata guardiansWallets, uint256 threshold)
        external
        returns (Safe account)
    {
        if (address(_guardiansMultisig) != address(0)) {
            revert GuardiansAlreadyExist();
        }

        account = _deploySafe({
            safeProxyFactory: _safeProxyFactory,
            safeSingleton: _safeImplementation,
            saltNonce: uint256(keccak256(abi.encode(guardiansWallets))),
            owners: guardiansWallets,
            threshold: threshold
        });

        _guardiansMultisig = account;

        emit GuardianAccountCreated(address(account));
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createPodAccount(address[] calldata podAccountOwners, uint256 threshold) external returns (Safe) {
        return _createPodAccount(podAccountOwners, threshold);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createPodAccountAndRegisterValidatorKey(
        address[] calldata podAccountOwners,
        uint256 podAccountThreshold,
        ValidatorKeyData calldata data
    ) external payable returns (Safe, IEigenPodProxy) {
        Safe account = _createPodAccount(podAccountOwners, podAccountThreshold);
        IEigenPodProxy proxy = registerValidatorKey(address(account), data);
        return (account, proxy);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function registerValidatorKey(address podAccount, ValidatorKeyData calldata data)
        public
        payable
        onlyPodAccountOwner(podAccount)
        returns (IEigenPodProxy)
    {
        // Sanity check on blsPubKey
        if (data.blsPubKey.length != 48) {
            revert InvalidBLSPubKey();
        }

        uint256 validatorBondRequirement = _getValidatorBondRequirement(data.raveEvidence, data.blsEncPrivKeyShares);
        if (msg.value != validatorBondRequirement) {
            revert InvalidAmount();
        }

        _validateCustody(data);

        // Creates Eigen Pod Proxy and Eigen Pod
        // Create2 with salt keccak256(data.blsPubKey) will revert on duplicate key registration
        IEigenPodProxy eigenPodProxy = _createEigenPodProxy(podAccount, keccak256(data.blsPubKey));

        // Mint pufETH to validator and lock it there
        _mint(address(eigenPodProxy), calculateETHToPufETHAmount(msg.value));

        // save necessary state
        // _eigenPodProxies[eigenPodProxy].status = VALIDATOR_STATUS.PROVISIONED;

        emit ValidatorKeyRegistered(address(eigenPodProxy), data.blsPubKey);

        return eigenPodProxy;
    }

    function _createEigenPodProxy(address account, bytes32 pubkeyHash)
        internal
        returns (IEigenPodProxy eigenPodProxy)
    {
        bytes memory deploymentData = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(
                EIGEN_POD_PROXY_BEACON,
                abi.encodeCall(EigenPodProxy.initialize, (payable(account), this, payable(account), 2 ether))
            )
        );

        // solhint-disable-next-line no-inline-assembly
        assembly {
            eigenPodProxy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), pubkeyHash)
        }

        if (address(eigenPodProxy) == address(0)) {
            revert Create2Failed();
        }

        // Save EigenPodProxy Information
        _eigenPodProxies[address(eigenPodProxy)].creator = msg.sender;
        _eigenPodProxies[address(eigenPodProxy)].pubKeyHash = pubkeyHash;

        return IEigenPodProxy(address(eigenPodProxy));
    }

    function _createPodAccount(address[] calldata podAccountOwners, uint256 threshold) internal returns (Safe) {
        Safe account = _deploySafe({
            safeProxyFactory: _safeProxyFactory,
            safeSingleton: _safeImplementation,
            saltNonce: block.timestamp, // TODO: change, two createPodAccounts will fail in the same block
            owners: podAccountOwners,
            threshold: threshold
        });

        emit PodAccountCreated(msg.sender, address(account));

        return account;
    }

    function _validateCustody(ValidatorKeyData calldata data) internal view {
        if (data.raveEvidence.length + data.blsEncPrivKeyShares.length == 0) {
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

        if (data.raveEvidence.length == 0) {
            // Second case:
            // No Enclave but gives custody
            return;
        }

        // Third case:
        // Enclave and gives custody
        // Do RAVE validation

        // TODO:

        // (bytes memory report, bytes memory sig, bytes memory leafX509Cert) =
        //     abi.decode(("bytes", "bytes", "bytes"), raveEvidence);
        // bytes memory key = verifyEnclaveKey(
        //     blsPubKey,
        //     blockNumber,
        //     report,
        //     sig,
        //     leafX509Cert,
        //     signingMod,
        //     signingExp,
        //     pufferPool.getSecureSignerMrenclave(),
        //     pufferPool.getSecureSignerMrsigner()
        // );
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
    function setCommissionDenominator(uint256 newValue) external onlyOwner {
        _setCommissionDenominator(newValue);
    }

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
    function getExecutionCommission() external view returns (uint256) {
        return _executionCommission;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getConsensusCommission() external view returns (uint256) {
        return _consensusCommission;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getAvsCommission() external view returns (uint256) {
        return _avsCommission;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getCommissionDenominator() external view returns (uint256) {
        return _commissionDenominator;
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

    function _setCommissionDenominator(uint256 newValue) internal {
        uint256 oldValue = _commissionDenominator;
        _commissionDenominator = newValue;
        emit CommissionDenominatorChanged(oldValue, newValue);
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

    function _getValidatorBondRequirement(bytes calldata raveEvidence, bytes[] calldata blsEncPrivKeyShares)
        internal
        view
        returns (uint256)
    {
        if (raveEvidence.length + blsEncPrivKeyShares.length == 0) {
            return _nonCustodialBondRequirement;
        }

        if (raveEvidence.length == 0) {
            return _nonEnclaveBondRequirement;
        }

        return _enclaveBondRequirement;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
