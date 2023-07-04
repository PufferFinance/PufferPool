// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IWETH9 } from "puffer/interface/IWETH9.sol";
import { IETHDepositor } from "puffer/interface/IETHDepositor.sol";
import { PufferPool } from "puffer/PufferPool.sol";

/**
 * @title ETHDepositor
 * @author Puffer finance
 * @notice Wraps ETH -> WETH and then deposits it to Puffer pool.
 */
contract ETHDepositor is IETHDepositor {
    /**
     * @notice Wrapped Ether
     */
    IWETH9 public immutable weth;
    /**
     * @notice PufferPool proxy contract
     */
    PufferPool public immutable pool;

    constructor(IWETH9 _weth, PufferPool _pool) {
        weth = _weth;
        pool = _pool;
    }

    /**
     * @inheritdoc IETHDepositor
     */
    function deposit(address recipientAddress) external payable returns (uint256 shares) {
        uint256 amount = msg.value;
        weth.deposit{ value: amount }();
        weth.approve(address(pool), amount);
        shares = pool.deposit(amount, recipientAddress);
    }
}
