// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title RewardsSplitter
 * @notice Contract for handing the execution rewards and mev boost
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract RewardsSplitter {
    address public immutable treasury;

    // TODO: logic for everything
    constructor(address pufferTreasury) {
        treasury = pufferTreasury;
    }

    function splitRewards() external {
        // ...
    }
}
