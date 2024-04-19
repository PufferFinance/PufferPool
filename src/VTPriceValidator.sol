// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";

/**
 * @title VTPriceValidator
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract VTPriceValidator is AccessManaged {
    /**
     * @notice Thrown if the new price is out of range
     */
    error InvalidPrice();

    /**
     * @notice Thrown if the new price cahnge tolerance is out of range
     */
    error InvalidPriceChangeToleranceBPS();

    uint256 constant _BPS_DECIMALS = 1e4; // 100%

    PufferOracleV2 internal immutable _ORACLE;

    uint256 public priceChangeToleranceBps; // 1% = 100

    constructor(PufferOracleV2 oracle, address accessManager, uint256 _priceChangeToleranceBps)
        AccessManaged(accessManager)
    {
        _ORACLE = oracle;
        priceChangeToleranceBps = _priceChangeToleranceBps;
    }

    /**
     * @notice Updates the allowed price change tolerance percentage
     * @dev Restricted to the Puffer DAO
     */
    function setPriceChangeToleranceBps(uint256 newValue) external restricted {
        if (newValue > _BPS_DECIMALS) {
            revert InvalidPriceChangeToleranceBPS();
        }

        priceChangeToleranceBps = newValue;
    }

    /**
     * @notice Updates the VT mint price on the PufferOracle
     * @dev Restricted to the Puffer Paymaster
     */
    function setValidatorTicketMintPricePrice(uint256 newPrice) external restricted {
        if (newPrice == 0) {
            revert InvalidPrice();
        }

        if (!_isWithinRange(newPrice)) {
            revert InvalidPrice();
        }

        _ORACLE.setMintPrice(newPrice);
    }

    // Helper function to determine if the new price is within 1% of the current price
    function _isWithinRange(uint256 newPrice) private view returns (bool) {
        uint256 oldPrice = _ORACLE.getValidatorTicketPrice();
        uint256 allowedDifference = (oldPrice * priceChangeToleranceBps) / _BPS_DECIMALS;

        // Addition and subtraction have bigger precedence than comparison
        // https://docs.soliditylang.org/en/latest/cheatsheet.html
        if (newPrice > oldPrice) {
            return newPrice <= oldPrice + allowedDifference;
        }

        return newPrice >= oldPrice - allowedDifference;
    }
}
