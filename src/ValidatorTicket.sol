// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20PermitUpgradeable } from "openzeppelin-upgrades/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { Context } from "@openzeppelin/contracts/utils/Context.sol";
import { ContextUpgradeable } from "openzeppelin-upgrades/utils/ContextUpgradeable.sol";

/**
 * @title ValidatorTicket
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract ValidatorTicket is ERC20PermitUpgradeable, Pausable {
    using SafeERC20 for address;
    using SafeTransferLib for address;
    using SafeTransferLib for address payable;

    /**
     * @dev A constant representing `100%`
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * FixedPointMathLib.WAD;

    address _oracle;
    address payable _pufferVault;
    address payable _guardians;
    address payable _treasury;
    uint256 _mintPrice;
    /// @dev This is how much ETH we immediately send to the PufferVault, holding the rest to later give to Guardians and Treasury
    uint256 _sendOnReceive;
    /// @dev This defines how much of this contract balance we give to the Treasury, giving the rest to Guardians
    uint256 _treasuryFee;

    /// @dev The caller is not authorized to call the function.
    error Unauthorized();

    /**
     * @notice Emitted when the price to mint VT is updated
     */
    event MintPriceUpdated(uint256 oldPrice, uint256 newPrice);

    /**
     * @notice Emitted when the ETH `amount` in wei is transferred to `to` address
     * @dev Signature "0xba7bb5aa419c34d8776b86cc0e9d41e72d74a893a511f361a11af6c05e920c3d"
     */
    event TransferredETH(address indexed to, uint256 amount);

    modifier onlyOracle() {
        if (msg.sender != _oracle) revert Unauthorized();
        _;
    }

    modifier onlyGuardians() {
        if (msg.sender != _guardians) revert Unauthorized();
        _;
    }

    constructor() payable {
        _disableInitializers();
    }

    function initialize(
        address oracle,
        address payable pufferVault,
        address payable guardians,
        address payable treasury,
        uint256 sendOnReceive,
        uint256 treasuryFee
    ) external initializer {
        __ERC20Permit_init("ValidatorTicket");
        __ERC20_init("ValidatorTicket", "VT");
        _oracle = oracle;
        _pufferVault = pufferVault;
        _guardians = guardians;
        _treasury = treasury;
        _sendOnReceive = sendOnReceive;
        _treasuryFee = treasuryFee;
    }

    function setSendOnReceive(uint256 newSendOnReceive) external onlyGuardians {
        _sendOnReceive = newSendOnReceive;
    }

    function setTreasuryFee(uint256 newTreasuryFee) external onlyGuardians {
        _treasuryFee = newTreasuryFee;
    }

    function setMintPrice(uint256 newPrice) external onlyOracle {
        uint256 oldPrice = _mintPrice;
        _mintPrice = newPrice;
        emit MintPriceUpdated(oldPrice, newPrice);
    }

    // Mints sender VT corresponding to sent ETH
    // Sends PufferVault due share, holding back rest to later distribute between Treasury and Guardians
    function mint() external payable whenNotPaused() {
        _mint(msg.sender, msg.value / _mintPrice);
        _sendETH(_pufferVault, msg.value, _sendOnReceive);
    }

    // This function distributes the contract's balance to Guardians and the Treasury
    function distribute() external onlyGuardians {
        _sendETH(_treasury, address(this).balance, _treasuryFee);
        _guardians.safeTransferETH(address(this).balance);
    }

    // _sendETH is sending ETH to trusted addresses (no reentrancy)
    function _sendETH(address to, uint256 amount, uint256 rate) internal returns (uint256 toSend) {
        toSend = FixedPointMathLib.fullMulDiv(amount, rate, _ONE_HUNDRED_WAD);

        if (toSend != 0) {
            emit TransferredETH(to, toSend);
            to.safeTransferETH(toSend);
        }
    }

    function _msgSender() internal view override (Context, ContextUpgradeable) returns (address) {
        return msg.sender;
    }

    function _msgData() internal view override (Context, ContextUpgradeable) returns (bytes calldata) {
        return msg.data;
    }
}
