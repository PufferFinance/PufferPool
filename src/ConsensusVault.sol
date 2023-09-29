// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { AbstractVault } from "puffer/AbstractVault.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";

/**
 * @title ConsensusVault
 * @notice Consensus rewards + full withdrawals are going to this pool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract ConsensusVault is AbstractVault {
    constructor(PufferProtocol pufferProtocol) payable AbstractVault(pufferProtocol) { }
}
