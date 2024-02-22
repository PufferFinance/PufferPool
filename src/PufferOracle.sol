// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";

/**
 * @title PufferOracle
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferOracle is IPufferOracle, AccessManaged {
    /**
     * @dev Price in ETH to mint one Validator Ticket
     */
    uint256 internal _validatorTicketPrice;

    constructor(address accessManager) AccessManaged(accessManager) {
        _setMintPrice(uint56(0.01 ether));
    }

    /**
     * @inheritdoc IPufferOracle
     */
    function getLockedEthAmount() external pure returns (uint256) {
        return 0;
    }

    /**
     * @inheritdoc IPufferOracle
     */
    function isOverBurstThreshold() external pure returns (bool) {
        return false;
    }

    /**
     * @inheritdoc IPufferOracle
     */
    function getValidatorTicketPrice() external view returns (uint256 pricePerVT) {
        return _validatorTicketPrice;
    }

    /**
     * @notice Updates the price to mint VT
     * @param newPrice The new price to set for minting VT
     * @dev Restricted to the DAO
     */
    function setMintPrice(uint56 newPrice) external restricted {
        _setMintPrice(newPrice);
    }

    function _setMintPrice(uint56 newPrice) internal {
        emit ValidatorTicketMintPriceUpdated(_validatorTicketPrice, newPrice);
        _validatorTicketPrice = newPrice;
    }
}
