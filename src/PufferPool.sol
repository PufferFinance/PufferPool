// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20Permit } from "openzeppelin/token/ERC20/extensions/ERC20Permit.sol";
import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferServiceManager } from "puffer/PufferServiceManager.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { IBeaconDepositContract } from "puffer/interface/IBeaconDepositContract.sol";

/**
 * @title PufferPool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferPool is IPufferPool, ERC20Permit {
    using SafeTransferLib for address;

    /**
     * @notice Address of the Beacon Chain Deposit Contract
     */
    IBeaconDepositContract public constant BEACON_DEPOSIT_CONTRACT =
        IBeaconDepositContract(0x00000000219ab540356cBB839Cbe05303d7705Fa);

    /**
     * @dev ETH Amount required for becoming a Validator
     */
    uint256 internal constant _32_ETHER = 32 ether;

    /**
     * @dev Minimum deposit amount in ETH
     */
    uint256 internal constant _MINIMUM_DEPOSIT_AMOUNT = 0.01 ether;

    /**
     * @notice PufferServiceManager
     */
    PufferServiceManager public immutable PUFFER_SERVICE_MANAGER;

    /**
     * @dev Locked ETH amount in Beacon Chain
     */
    uint256 internal _lockedETHAmount;

    /**
     * @dev New rewards amount
     */
    uint256 internal _newETHRewardsAmount;

    modifier onlyPufferServiceManager() {
        if (msg.sender != address(PUFFER_SERVICE_MANAGER)) {
            revert Unauthorized();
        }
        _;
    }

    constructor(PufferServiceManager serviceManager) payable ERC20("Puffer ETH", "pufETH") ERC20Permit("pufETH") {
        PUFFER_SERVICE_MANAGER = serviceManager;
    }

    /**
     * @notice no calldata automatically triggers the depositETH for `msg.sender`
     */
    receive() external payable {
        depositETH();
    }

    /**
     * @inheritdoc IPufferPool
     */
    function depositETH() public payable returns (uint256) {
        if (msg.value < _MINIMUM_DEPOSIT_AMOUNT) {
            revert InsufficientETH();
        }

        uint256 pufETHAmount = _calculateETHToPufETHAmount(msg.value);

        emit Deposited(msg.sender, msg.value, pufETHAmount);

        _mint(msg.sender, pufETHAmount);

        return pufETHAmount;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function burn(uint256 pufETHAmount) external {
        _burn(msg.sender, pufETHAmount);
    }

    function createValidator(
        bytes calldata pubKey,
        bytes calldata withdrawalCredentials,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external onlyPufferServiceManager {
        BEACON_DEPOSIT_CONTRACT.deposit{ value: _32_ETHER }({
            pubkey: pubKey,
            withdrawal_credentials: withdrawalCredentials,
            signature: signature,
            deposit_data_root: depositDataRoot
        });
    }

    function setNewRewardsETHAmount(uint256 amount) external {
        // TODO: everything
        _newETHRewardsAmount = amount;
    }

    function updateETHBackingAmount(uint256 amount) external {
        // TODO: only guardians
        _lockedETHAmount = amount;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function calculateETHToPufETHAmount(uint256 amount) public view returns (uint256) {
        return FixedPointMathLib.divWad(amount, _getPufETHtoETHExchangeRate(0));
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
        // slither-disable-next-line incorrect-equality
        if (pufETHSupply == 0) {
            return FixedPointMathLib.WAD;
        }
        // address(this).balance - ethDepositedAmount is actually balance of this contract before the deposit
        uint256 exchangeRate = FixedPointMathLib.divWad(
            getLockedETHAmount() + getNewRewardsETHAmount() + PUFFER_SERVICE_MANAGER.getWithdrawalPool().balance
                + PUFFER_SERVICE_MANAGER.getExecutionRewardsVault().balance
                + PUFFER_SERVICE_MANAGER.getConsensusVault().balance + (address(this).balance - ethDepositedAmount),
            pufETHSupply
        );

        return exchangeRate;
    }

    /**
     * @dev Internal function for calculating the ETH to pufETH amount when ETH is being sent in the transaction
     */
    function _calculateETHToPufETHAmount(uint256 amount) public view returns (uint256) {
        return FixedPointMathLib.divWad(amount, _getPufETHtoETHExchangeRate(amount));
    }
}
