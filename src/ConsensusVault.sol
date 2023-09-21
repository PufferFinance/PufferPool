// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { AbstractVault } from "puffer/AbstractVault.sol";

/**
 * @title ConsensusVault
 * @notice Consensus rewards + full withdrawals are going to this pool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract ConsensusVault is AbstractVault {
    constructor(PufferPool pool) payable AbstractVault(pool) { }
}
