// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @custom:storage-location erc7201:PufferPoolStorage.storage
 */
struct PufferPoolStorage {
    /**
     * @dev Unlocked ETH amount
     * Slot 0
     */
    uint256 ethAmount;
    /**
     * @dev Locked ETH amount in Beacon Chain
     * Slot 1
     */
    uint256 lockedETH;
    /**
     * @dev pufETH total token supply
     * Slot 2
     */
    uint256 pufETHTotalSupply;
    /**
     * @dev Block number for when the values were updated
     * Slot 3
     */
    uint256 lastUpdate;
}
