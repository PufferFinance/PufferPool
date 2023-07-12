// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20PermitUpgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "openzeppelin-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { OwnableUpgradeable } from "openzeppelin-upgradeable/access/OwnableUpgradeable.sol";
import { PausableUpgradeable } from "openzeppelin-upgradeable/security/PausableUpgradeable.sol";
import { SafeDeployer } from "puffer/SafeDeployer.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";

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
    address public immutable EIGEN_POD_PROXY_BEACON;
    /**
     * @notice Exchange rate 1 is represented as 10 ** 18
     */
    uint256 internal constant _ONE = 10 ** 18;

    /**
     * @notice Minimum deposit amount in ETH
     */
    uint256 internal constant _MINIMUM_DEPOSIT_AMOUNT = 0.01 ether;

    /**
     * @notice ETH Amount That Puffer is supplying to Validator
     */
    uint256 internal constant _THIRTY_ETHER = 30 ether;

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

    constructor(address beacon) {
        EIGEN_POD_PROXY_BEACON = beacon;
        _disableInitializers();
    }

    function initialize() external initializer {
        __ReentrancyGuard_init(); // TODO: figure out if really need it?
        __UUPSUpgradeable_init();
        __ERC20_init("Puffer ETH", "pufETH");
        __Pausable_init();
        __Ownable_init();
    }

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

    receive() external payable { }

    // function extractEnclaveEthKeys(bytes[] memory payloads) internal override returns (bytes[] memory pubKeys) { }

    // function decodeToEthPubkey(bytes memory enclavePayload) internal pure override returns (bytes memory pubKey) { }

    // function registerValidatorKey() external payable { }

    /**
     * @inheritdoc IPufferPool
     */
    function deposit(address recipient) external payable whenNotPaused {
        if (msg.value < _MINIMUM_DEPOSIT_AMOUNT) {
            revert AmountTooSmall();
        }

        uint256 pufETHAmount = calculateETHToPufETHAmount(msg.value);

        _mint(recipient, pufETHAmount);

        emit Deposited(msg.sender, recipient, msg.value, pufETHAmount);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function withdraw(address ethRecipient, uint256 pufETHAmount) external whenNotPaused {
        uint256 ethAmount = calculatePufETHtoETHAmount(pufETHAmount);

        _burn(msg.sender, pufETHAmount);

        _safeTransferETH(ethRecipient, ethAmount);

        emit Withdrawn(msg.sender, ethRecipient, pufETHAmount, ethAmount);
    }

    function provideRemainingETH() external onlyGuardians {
        // TODO: validations

        address eingenPodProxy;
        uint256 validatorIdx;

        // Update locked ETH Amount
        _lockedETHAmount += _THIRTY_ETHER;

        _safeTransferETH(eingenPodProxy, _THIRTY_ETHER);

        emit ETHProvisioned(eingenPodProxy, validatorIdx, block.timestamp);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createGuardianAccount(
        address safeProxyFactory,
        address safeImplementation,
        bytes[] calldata guardiansEnclavePubKeys,
        address[] calldata guardiansWallets,
        bytes32 mrenclave,
        bytes calldata emptyData
    ) external returns (Safe account) {
        if (address(_guardiansMultisig) != address(0)) {
            revert();
        }
        // TODO: validations, other logic

        require(emptyData.length == 0);

        account = _deploySafe({
            safeProxyFactory: address(safeProxyFactory),
            safeSingleton: address(safeImplementation),
            saltNonce: uint256(mrenclave),
            owners: guardiansWallets,
            emptyData: emptyData,
            threshold: _getThreshold(guardiansWallets.length)
        });

        _guardiansMultisig = account;

        emit GuardianAccountCreated(mrenclave, address(account));
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createPodAccount(
        address safeProxyFactory,
        address safeImplementation,
        bytes[] calldata podEnclavePubKeys,
        address[] calldata podWallets,
        bytes32 mrenclave,
        bytes calldata emptyData
    ) external returns (Safe account) {
        // TODO: validations, other logic

        require(emptyData.length == 0);

        account = _deploySafe({
            safeProxyFactory: address(safeProxyFactory),
            safeSingleton: address(safeImplementation),
            saltNonce: uint256(mrenclave),
            owners: podWallets,
            emptyData: emptyData,
            threshold: _getThreshold(podWallets.length)
        });

        BeaconProxy eigenPodProxy =
        new BeaconProxy(EIGEN_POD_PROXY_BEACON, abi.encodeCall(EigenPodProxy.initialize, (address(account), address(this))));

        // TODO: other logic, remove this assert
        assert(EigenPodProxy(address(eigenPodProxy)).getManager() == address(this));

        emit PodAccountCreated(mrenclave, address(account));
    }

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
    function getPufETHtoETHExchangeRate() public view returns (uint256) {
        return _getPufETHtoETHExchangeRate(0);
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

    function setNewRewardsETHAmount(uint256 amount) external {
        // TODO: everything
        _newETHRewardsAmount = amount;
    }

    // Only owner

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

    // TODO: timelock on upgrade?
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner { }

    function _getThreshold(uint256 numberOfOwners) internal pure returns (uint256) {
        // TODO: figure out the right numbers
        if (numberOfOwners > 5) {
            return 4;
        }

        if (numberOfOwners > 3) {
            return 3;
        }

        return 1;
    }

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

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
