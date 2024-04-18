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
     * @dev Signature "0x00bfc921"
     */
    error InvalidPrice();

    PufferOracleV2 internal immutable _ORACLE;

    constructor(PufferOracleV2 oracle, address accessManager) AccessManaged(accessManager) {
        _ORACLE = oracle;
    }

    /**
     * @notice Updates the VT mint price on the PufferOracle
     * @dev Restricted to the Puffer Paymaster
     */
    function setValidatorTicketMintPricePrice(uint256 newPrice) external restricted {
        if (newPrice == 0) {
            revert InvalidPrice();
        }

        if (!_isWithinOnePercent(newPrice)) {
            revert InvalidPrice();
        }

        _ORACLE.setMintPrice(newPrice);
    }

    // Helper function to determine if the new price is within 1% of the current price
    function _isWithinOnePercent(uint256 newPrice) private view returns (bool) {
        uint256 oldPrice = _ORACLE.getValidatorTicketPrice();
        uint256 onePercent = oldPrice / 100;

        // Addition and subtraction have bigger precedence than comparison
        // https://docs.soliditylang.org/en/latest/cheatsheet.html
        if (newPrice > oldPrice) {
            return newPrice <= oldPrice + onePercent;
        }

        return newPrice >= oldPrice - onePercent;
    }
}
