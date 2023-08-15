// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";

/**
 * @title RewardsSplitter
 * @notice Contract for handing the execution rewards and MEV boost
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract RewardsSplitter is Initializable {
    /**
     * @dev Thrown if the msg.sender is unauthorized.
     */
    error Unauthorized();

    event ETHReceived(uint256 amount);
    event RewardsRecipientChanged(address oldRewardsRecipient, address newRewardsRecipient);

    IPufferPool internal _pool;
    address internal _podAccount;
    address internal _rewardsRecipient;

    function initialize(IPufferPool pool, address podAccount) external initializer {
        _podAccount = podAccount;
        _pool = pool;
    }

    function setRewardsRecipient(address recipient) external {
        if (msg.sender != _podAccount) {
            revert Unauthorized();
        }
        address oldRecipient = _rewardsRecipient;
        _rewardsRecipient = recipient;
        emit RewardsRecipientChanged(oldRecipient, recipient);
    }

    receive() external payable {
        IPufferPool pool = _pool;

        // Send the execution comission to PufferPool
        uint256 executionComission = pool.getExecutionAmount(msg.value);
        SafeTransferLib.safeTransferETH(address(pool), executionComission);

        // Send the rest to rewards recipient
        SafeTransferLib.safeTransferETH(_rewardsRecipient, msg.value - executionComission);

        emit ETHReceived(msg.value);
    }
}
