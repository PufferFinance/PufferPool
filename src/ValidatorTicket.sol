// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { ERC20PermitUpgradeable } from "openzeppelin-upgrades/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { ValidatorTicketStorage } from "src/ValidatorTicketStorage.sol";
import { SafeCastLib } from "solady/utils/SafeCastLib.sol";

/**
 * @title ValidatorTicket
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract ValidatorTicket is
    ValidatorTicketStorage,
    UUPSUpgradeable,
    AccessManagedUpgradeable,
    ERC20PermitUpgradeable
{
    using SafeERC20 for address;
    using SafeTransferLib for address;
    using SafeTransferLib for address payable;

    error InvalidAmount();

    /**
     * @dev Puffer Finance treasury
     */
    address payable public immutable TREASURY;

    /**
     * @notice Emitted when the price to mint VT is updated
     */
    event MintPriceUpdated(uint256 oldPrice, uint256 newPrice);

    /**
     * @notice Emitted when the ETH `amount` in wei is transferred to `to` address
     * @dev Signature "0xba7bb5aa419c34d8776b86cc0e9d41e72d74a893a511f361a11af6c05e920c3d"
     */
    event TransferredETH(address indexed to, uint256 amount);

    /**
     * @notice Emitted when the protocol fee rate is changed
     * @dev Signature "0xb51bef650ff5ad43303dbe2e500a74d4fd1bdc9ae05f046bece330e82ae0ba87"
     */
    event ProtocolFeeChanged(uint256 oldTreasuryFee, uint256 newTreasuryFee);

    /**
     * @notice Emitted when the protocol fee rate is changed
     * @dev Signature "0x0a3e0a163d4dfba5f018c5c1e2214007151b3abb0907e3ae402ae447c7e1bc47"
     */
    event GuardiansFeeChanged(uint256 oldGuardiansFee, uint256 newGuardiansFee);

    /**
     * @notice Thrown if the oracle tries to submit invalid data
     * @dev Signature "0x5cb045db"
     */
    error InvalidData();

    constructor(address payable treasury) {
        TREASURY = treasury;
        _disableInitializers();
    }

    function initialize(
        address accessManager,
        uint256 treasuryFeeRate,
        uint256 guardiansFeeRate,
        uint56 initialMintPrice
    ) external initializer {
        __AccessManaged_init(accessManager);
        __ERC20_init("Puffer Validator Ticket", "VT");
        __ERC20Permit_init("Puffer Validator Ticket");
        _setProtocolFeeRate(treasuryFeeRate);
        _setGuardiansFeeRate(guardiansFeeRate);
        _setMintPrice(initialMintPrice);
    }

    /**
     * @notice Mints sender VT corresponding to sent ETH
     * @param recipient The address to mint VT to
     * @dev restricted modifier is also used as `whenNotPaused`
     * @notice Sends PufferVault due share, holding back rest to later distribute between Treasury and Guardians
     */
    function purchaseValidatorTicket(address recipient) external payable restricted {
        ValidatorTicket storage $ = _getValidatorTicketStorage();

        uint256 mintPrice = $.mintPrice;

        // We are only accepting deposits in multiples of mintPrice
        if (msg.value % mintPrice != 0) {
            revert InvalidAmount();
        }

        //@todo burst threshold

        // Send ETH to treasury
        _sendETH(TREASURY, msg.value, $.protocolFeeRate);

        // Do guardians accounting
        uint256 guardiansAmount = FixedPointMathLib.fullMulDiv(msg.value, $.guardiansFeeRate, _ONE_HUNDRED_WAD);
        $.guardiansBalance += SafeCastLib.toUint72(guardiansAmount);

        // The remainder belongs to PufferVault
        _mint(recipient, msg.value / mintPrice);
    }

    /**
     * @notice Transfers the remaining ETH balance to the PufferVault
     * @param pufferVault The address of the PufferVault to transfer ETH to
     * @dev Restricted access with timelock
     */
    function transferETHToPufferVault(address pufferVault) external restricted {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        uint256 amount = address(this).balance - $.guardiansBalance;
        pufferVault.safeTransferETH(amount);
    }

    /**
     * @notice Burns `amount` from the transaction sender
     * @dev Signature "0x42966c68"
     */
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /**
     * @notice Transfers ETH to the specified guardians address
     * @param guardians The address of the guardians to transfer ETH to
     * @dev Restricted access with timelock
     */
    function transferETHToGuardians(address guardians) external restricted {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        $.guardiansBalance = 0;
        guardians.safeTransferETH($.guardiansBalance);
    }

    /**
     * @notice Updates the treasury fee
     * @dev Restricted access
     * @param newProtocolFeeRate The new treasury fee to set
     */
    function setProtocolFeeRate(uint256 newProtocolFeeRate) external restricted {
        _setProtocolFeeRate(newProtocolFeeRate);
    }

    /**
     * @notice Retrieves the current mint price for a Validator Ticket
     * @return The current mint price
     */
    function getValidatorTicketPrice() external view returns (uint256) {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        return $.mintPrice;
    }

    /**
     * @notice Retrieves the current protocol fee rate
     * @return The current protocol fee rate
     */
    function getProtocolFeeRate() external view returns (uint256) {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        return $.protocolFeeRate;
    }

    /**
     * @notice Retrieves the current balance held for guardians
     * @return The current guardians balance
     */
    function getGuardiansBalance() external view returns (uint256) {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        return $.guardiansBalance;
    }

    /**
     * @notice Updates the price to mint VT
     * @param newPrice The new price to set for minting VT
     */
    function setMintPrice(uint56 newPrice) external restricted {
        _setMintPrice(newPrice);
    }

    function _setMintPrice(uint56 newPrice) internal {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        uint256 oldPrice = $.mintPrice;
        $.mintPrice = newPrice;
        emit MintPriceUpdated(oldPrice, newPrice);
    }

    /**
     * @dev _sendETH is sending ETH to trusted addresses (no reentrancy protection)
     */
    function _sendETH(address to, uint256 amount, uint256 rate) internal returns (uint256 toSend) {
        toSend = FixedPointMathLib.fullMulDiv(amount, rate, _ONE_HUNDRED_WAD);

        if (toSend != 0) {
            emit TransferredETH(to, toSend);
            to.safeTransferETH(toSend);
        }
    }

    function _setProtocolFeeRate(uint256 newProtocolFeeRate) internal {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        // Treasury fee can not be bigger than 10%
        if ($.protocolFeeRate > (10 * FixedPointMathLib.WAD)) {
            revert InvalidData();
        }
        uint256 oldProtocolFeeRate = uint256($.protocolFeeRate);
        $.protocolFeeRate = SafeCastLib.toUint64(newProtocolFeeRate);
        emit ProtocolFeeChanged(oldProtocolFeeRate, newProtocolFeeRate);
    }

    function _setGuardiansFeeRate(uint256 newGuardiansFeeRate) internal {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        // Treasury fee can not be bigger than 10%
        if ($.protocolFeeRate > (10 * FixedPointMathLib.WAD)) {
            revert InvalidData();
        }
        uint256 oldGuardiansFeeRate = uint256($.guardiansFeeRate);
        $.guardiansFeeRate = SafeCastLib.toUint64(newGuardiansFeeRate);
        emit GuardiansFeeChanged(oldGuardiansFeeRate, newGuardiansFeeRate);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
