// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title IPufferOracle
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferOracle {
    /**
     * @notice Thrown if Guardians try to re-submit the backing data
     * @dev Signature "0xf93417f7"
     */
    error OutsideUpdateWindow();

    /**
     * @notice Emitted when the Guardians update state of the protocol
     * @param blockNumber is the block number of the update
     * @param lockedETH is the locked ETH amount in Beacon chain
     */
    event BackingUpdated(uint256 indexed blockNumber, uint256 lockedETH);

    /**
     * @notice Emitted when the price to mint VT is updated
     */
    event ValidatorTicketMintPriceUpdated(uint256 oldPrice, uint256 newPrice);

    /**
     * @notice Retrieves the current mint price for a Validator Ticket
     * @return The current mint price
     */
    function getValidatorTicketPrice() external view returns (uint256);
}
