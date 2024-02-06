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
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";

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

    IPufferOracle public immutable PUFFER_ORACLE;

    address payable public immutable GUARDIAN_MODULE;

    address payable public immutable PUFFER_VAULT;

    constructor(address payable guardianModule, address payable pufferVault, IPufferOracle pufferOracle) {
        PUFFER_ORACLE = pufferOracle;
        GUARDIAN_MODULE = guardianModule;
        PUFFER_VAULT = pufferVault;
        _disableInitializers();
    }

    function initialize(address accessManager, uint256 treasuryFeeRate, uint256 guardiansFeeRate)
        external
        initializer
    {
        __AccessManaged_init(accessManager);
        __ERC20_init("Puffer Validator Ticket", "VT");
        __ERC20Permit_init("Puffer Validator Ticket");
        _setProtocolFeeRate(treasuryFeeRate);
        _setGuardiansFeeRate(guardiansFeeRate);
    }

    /**
     * @notice Mints sender VT corresponding to sent ETH
     * @param recipient The address to mint VT to
     * @dev restricted modifier is also used as `whenNotPaused`
     * @notice Sends PufferVault due share, holding back rest to later distribute between Treasury and Guardians
     */
    function purchaseValidatorTicket(address recipient) external payable restricted {
        ValidatorTicket storage $ = _getValidatorTicketStorage();

        uint256 mintPrice = PUFFER_ORACLE.getValidatorTicketPrice();

        // We are only accepting deposits in multiples of mintPrice
        if (msg.value % mintPrice != 0) {
            revert InvalidAmount();
        }
        //@todo burst threshold

        // Treasury amount is staying in this contract
        uint256 treasuryAmount = FixedPointMathLib.fullMulDiv(msg.value, $.protocolFeeRate, _ONE_HUNDRED_WAD);
        // Guardians get the cut right away
        uint256 guardiansAmount = _sendETH(GUARDIAN_MODULE, msg.value, $.guardiansFeeRate);
        // The remainder belongs to PufferVault
        uint256 pufferVaultAmount = msg.value - (treasuryAmount + guardiansAmount);
        PUFFER_VAULT.safeTransferETH(pufferVaultAmount);

        // The remainder belongs to PufferVault
        _mint(recipient, (msg.value / mintPrice) * 1 ether); // * 1 ether is to upscale amount to 18 decimals
    }

    /**
     * @notice Burns `amount` from the transaction sender
     * @dev Signature "0x42966c68"
     */
    function burn(uint256 amount) external restricted {
        _burn(msg.sender, amount);
    }

    /**
     * @notice Updates the treasury fee
     * @dev Restricted access
     * @param newProtocolFeeRate The new treasury fee rate
     */
    function setProtocolFeeRate(uint256 newProtocolFeeRate) external restricted {
        _setProtocolFeeRate(newProtocolFeeRate);
    }

    /**
     * @notice Updates the guardians fee rate
     * @dev Restricted access
     * @param newGuardiansFeeRate The new guardians fee rate
     */
    function setGuardiansFeeRate(uint256 newGuardiansFeeRate) external restricted {
        _setGuardiansFeeRate(newGuardiansFeeRate);
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
