// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { PufferProtocolHandler } from "../handlers/PufferProtocolHandler.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { TestHelper } from "../helpers/TestHelper.sol";

contract PufferProtocolInvariants is TestHelper {
    PufferProtocolHandler handler;

    function setUp() public override {
        super.setUp();

        handler = new PufferProtocolHandler(this, pool, withdrawalPool, pufferProtocol, guardiansEnclavePks);

        // Set handler as a target contract for invariant test
        targetContract(address(handler));
    }

    // // Guardian multisig is not supposed to change
    function invariant_guardiansCanNeverChange() public {
        assertTrue(address(guardiansSafe) == address(pufferProtocol.GUARDIANS()));
    }

    function invariant_pufferPoolETHCanOnlyGoUp() public {
        // PufferPool's ETH balance can only grow, unless it is `provisionNode`
        if (handler.ethLeavingThePool()) {
            assertTrue(address(pool).balance < handler.previousBalance());
        } else {
            assertTrue(address(pool).balance >= handler.previousBalance());
        }
    }

    // pufETH should always be worth more than ETH
    function invariant_pufEthToETHRate() public {
        // Exchange rate should always be bigger than 1:1, we are not supposed to be losing anything with this setup ATM
        assertTrue(pool.getPufETHtoETHExchangeRate() >= 1 ether);
    }

    // Sanity check for our calculations
    // function invariant_depositedShouldBeBiggerThanTotalSupply() public {
    //     // Read total supply from oracle update, not from pufferPool
    //     uint256 totalSupply = pufferProtocol.getPuferPoolStorage().pufETHTotalSupply;

    //     uint256 amount = pool.calculatePufETHtoETHAmount(totalSupply);

    //     uint256 totalEth = handler.ghost_eth_deposited_amount() + handler.ghost_locked_amount() + handler.ghost_eth_rewards_amount();
    //     // The total amount deposited + rewards should be bigger than all of pufETH converted to ETH calculation
    //     assertTrue(totalEth >= amount);
    // }

    function invariant_callSummary() public view {
        handler.callSummary();
    }
}
