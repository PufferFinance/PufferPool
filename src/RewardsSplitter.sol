// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title RewardsSplitter
 * @notice Contract for handing the execution rewards and mev boost
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract RewardsSplitter {
    event ETHReceived(uint256 amount);

    receive() external payable {
        // TODO: logic
        emit ETHReceived(msg.value);
    }
}
