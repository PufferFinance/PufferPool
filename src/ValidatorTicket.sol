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
     * @dev Puffer Finance Puffer Vault
     */
    address payable public immutable PUFFER_VAULT;

    /**
     * @notice Emitted when the price to mint VT is updated
     * @dev Signature "0x2e1c9e000c6e8dda4d03536adb13b7cb6034ccff90d17f01de381e4d5097b525"
     */
    event MintPriceUpdated(uint256 oldPrice, uint256 newPrice);

    /**
     * @notice Emitted when the ETH `amount` in wei is transferred to `to` address
     * @dev Signature "0xba7bb5aa419c34d8776b86cc0e9d41e72d74a893a511f361a11af6c05e920c3d"
     */
    event TransferredETH(address indexed to, uint256 amount);

    /**
     * @notice Emitted when the rate of deposited funds sent to PufferVault is changed
     * @dev Signature "0xac33dee2c4f3f5f235f679660c351c116a4d5dab91498a0954c85ad535bee25b"
     */
    event SendOnReceiveFeeChanged(uint256 oldTreasuryFee, uint256 newTreasuryFee);

    /**
     * @notice Emitted when the treasury fee rate is changed
     * @dev Signature "0x77952d80680a32b88518cb8568afaa79f18db1b1239e2dc29350a2094e8a6a79"
     */
    event TreasuryFeeChanged(uint256 oldGuardiansFee, uint256 newGuardiansFee);

    /**
     * @notice Thrown if the oracle tries to submit invalid data
     * @dev Signature "0x5cb045db"
     */
    error InvalidData();

    constructor(address payable treasury, address payable pufferVault) {
        TREASURY = treasury;
        PUFFER_VAULT = pufferVault;
        _disableInitializers();
    }

    function initialize(
        address accessManager,
        address oracle,
        address payable guardians,
        uint256 sendOnReceive,
        uint256 treasuryFee,
        uint256 initialMintPrice
    ) external initializer {
        __AccessManaged_init(accessManager);
        _setOracle(oracle);
        _setGuardians(guardians);
        __ERC20_init("Validator Ticket", "VT");
        __ERC20Permit_init("Validator Ticket");
        _setSendOnReceive(sendOnReceive);
        _setTreasuryFee(treasuryFee);
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

        _sendETH(PUFFER_VAULT, msg.value, $.sendOnReceive);

        _mint(recipient, msg.value / $.mintPrice);
    }

    /**
     * @notice This function distributes the contract's balance to Guardians and the Treasury
     */
    function distribute() external restricted {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        _sendETH(TREASURY, address(this).balance, $.treasuryFee);
        $.guardians.safeTransferETH(address(this).balance);
    }

    /**
     * @notice Burns `amount` from the transaction sender
     * @dev Signature "0x42966c68"
     */
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /**
     * @notice Updates the treasury fee
     * @dev Restricted access
     * @param newTreasuryFee The new treasury fee to set
     */
    function setTreasuryFee(uint256 newTreasuryFee) external restricted {
        _setTreasuryFee(newTreasuryFee);
    }

    /**
     * @notice Updates the amount of ETH sent to PufferVault upon minting VTs
     * @dev Restricted access
     * @param newSendOnReceive The new fee to set
     */
    function setSendOnReceive(uint256 newSendOnReceive) external restricted {
        _setSendOnReceive(newSendOnReceive);
    }

    /**
     * @notice Updates the price to mint VT
     * @param newPrice The new price to set for minting VT
     */
    function setMintPrice(uint256 newPrice) external restricted {
        _setMintPrice(newPrice);
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
    function getSendOnReceiveFee() external view returns (uint256) {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        return $.sendOnReceive;
    }

    function _setMintPrice(uint256 newPrice) internal {
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

    function _setSendOnReceive(uint256 newSendOnReceive) internal {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        uint256 oldSendOnReceive = uint256($.sendOnReceive);
        $.sendOnReceive = newSendOnReceive;
        emit SendOnReceiveFeeChanged(oldSendOnReceive, newSendOnReceive);
    }

    function _setTreasuryFee(uint256 newTreasuryFeeRate) internal {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        // Treasury fee can not be bigger than 10%
        if (newTreasuryFeeRate > (10 * FixedPointMathLib.WAD)) {
            revert InvalidData();
        }
        uint256 oldTreasuryFeeRate = uint256($.treasuryFee);
        $.treasuryFee = SafeCastLib.toUint64(newTreasuryFeeRate);
        emit TreasuryFeeChanged(oldTreasuryFeeRate, newTreasuryFeeRate);
    }

    function _setGuardians(address payable guardians) internal {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        $.guardians = guardians;
    }

    function _setOracle(address oracle) internal {
        ValidatorTicket storage $ = _getValidatorTicketStorage();
        $.oracle = oracle;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
