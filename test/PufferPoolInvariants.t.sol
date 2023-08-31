// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { PufferPoolHandler } from "./handlers/PufferPoolHandler.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { console } from "forge-std/console.sol";
import { GuardianHelper } from "./helpers/GuardianHelper.sol";

contract PufferPoolInvariants is GuardianHelper {
    PufferPoolHandler handler;

    function setUp() public override {
        super.setUp();

        // Create guardians in setup
        _createGuardians();

        handler = new PufferPoolHandler(pool, withdrawalPool, guardiansEnclavePks);

        // Set handler as a target contract for invariant test
        targetContract(address(handler));
    }

    function invariant_pufferPoolETHCanOnlyGoUp() public {
        // PufferPool's ETH balance can only grow, unless it is `provisionPodETH`
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
    function invariant_depositedShouldBeBiggerThanTotalSupply() public {
        uint256 amount = pool.calculatePufETHtoETHAmount(pool.totalSupply());
        // The total amount deposited + rewards should be bigger than all of pufETH converted to ETH calculation
        assertTrue(handler.ghost_eth_deposited_amount() + handler.ghost_eth_rewards_amount() >= amount);
    }

    function invariant_callSummary() public view {
        handler.callSummary();
    }
}
