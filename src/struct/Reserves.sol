// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @param newLockedETH The new locked ETH amount in Beacon chain
 * @param blockNumber The block number of the update
 * @param numberOfActivePufferValidators The number of active Puffer validators
 * @param totalNumberOfValidators The total number of active validators
 * @param guardianSignatures The signatures of the Guardians
 */
struct Reserves {
    uint152 newLockedETH;
    uint56 blockNumber;
    uint24 numberOfActivePufferValidators;
    uint24 totalNumberOfValidators;
}
