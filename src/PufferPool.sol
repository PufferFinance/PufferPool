// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20Upgradeable } from "openzeppelin-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import { ReentrancyGuardUpgradeable } from "openzeppelin-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { OwnableUpgradeable } from "openzeppelin-upgradeable/access/OwnableUpgradeable.sol";
import { IERC20Upgradeable } from "openzeppelin-upgradeable/token/ERC20/IERC20Upgradeable.sol";
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
    SafeDeployer,
    OwnableUpgradeable,
    PausableUpgradeable,
    ERC20Upgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    uint256 internal constant _MINIMUM_DEPOSIT_AMOUNT = 0.01 ether;

    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializer
     */
    function initialize() external initializer {
        __ReentrancyGuard_init(); // TODO: figure out if really need it?
        __UUPSUpgradeable_init();
        __ERC20_init("Puffer ETH", "pufETH");
        __Pausable_init();
        __Ownable_init();
    }

    /**
     * @dev Only for registered Eigen Pods
     */
    modifier onlyPod() {
        // TODO logic:
        _;
    }

    // function extractEnclaveEthKeys(bytes[] memory payloads) internal override returns (bytes[] memory pubKeys) { }

    // function decodeToEthPubkey(bytes memory enclavePayload) internal pure override returns (bytes memory pubKey) { }

    /**
     * @inheritdoc IPufferPool
     */
    function deposit(address recipient) external payable whenNotPaused {
        if (msg.value < _MINIMUM_DEPOSIT_AMOUNT) {
            revert AmountTooSmall();
        }

        _mint(recipient, msg.value);

        emit Deposited(recipient, msg.value);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function redeem(address recipient, uint256 pufETHAmount) external whenNotPaused {
        // TODO: other logic

        _burn(msg.sender, pufETHAmount);

        emit Burned(msg.sender, pufETHAmount, recipient);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function createGuardianAccount(
        address safeProxyFactory,
        address safeImplementation,
        bytes[] calldata guardiansEnclavePubKeys,
        address[] calldata guardiansWallets,
        bytes32 mrenclave
    ) external returns (Safe account) {
        // TODO: validations, other logic

        account = _deploySafe({
            safeProxyFactory: address(safeProxyFactory),
            safeSingleton: address(safeImplementation),
            saltNonce: uint256(mrenclave),
            owners: guardiansWallets,
            threshold: _getThreshold(guardiansWallets.length)
        });

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
        bytes32 mrenclave
    ) external returns (Safe account) {
        // TODO: validations, other logic

        account = _deploySafe({
            safeProxyFactory: address(safeProxyFactory),
            safeSingleton: address(safeImplementation),
            saltNonce: uint256(mrenclave),
            owners: podWallets,
            threshold: _getThreshold(podWallets.length)
        });

        // TODO: maybe Minimal clones for this?
        EigenPodProxy eigenPodProxy = new EigenPodProxy(address(account), address(this));

        emit PodAccountCreated(mrenclave, address(account));
    }

    function registerValidatorKey() external payable { }

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
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
