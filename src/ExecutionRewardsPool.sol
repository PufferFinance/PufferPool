// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/**
 * @title ExecutionRewardsPool
 * @notice This is the pool for receiving the execution rewards
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract ExecutionRewardsPool {
    using SafeTransferLib for address;

    event ExecutionRewardReceived(uint256 amount);

    PufferPool public immutable POOL;

    constructor(PufferPool pufferPool) {
        POOL = pufferPool;
    }

    receive() external payable {
        emit ExecutionRewardReceived(msg.value);
    }

    /**
     * @notice Transfers ETH to WithdrawalPool
     */
    function transferETH(uint256 amount) external {
        require(msg.sender == POOL.getWithdrawalPool());
        msg.sender.safeTransferETH(amount);
    }
}
