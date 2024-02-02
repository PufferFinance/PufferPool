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
     * @param ethAmount is the ETH amount that is not locked in Beacon chain
     * @param lockedETH is the locked ETH amount in Beacon chain
     * @param pufETHTotalSupply is the total supply of the pufETH
     */
    event BackingUpdated(uint256 ethAmount, uint256 lockedETH, uint256 pufETHTotalSupply, uint256 blockNumber);
}
