// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { PufferProtocolHandler } from "../handlers/PufferProtocolHandler.sol";
import { TestHelper } from "../helpers/TestHelper.sol";

contract PufferProtocolInvariants is TestHelper {
    PufferProtocolHandler handler;

    function setUp() public override {
        super.setUp();

        vm.startPrank(DAO);
        pufferProtocol.setValidatorLimitPerInterval(200);
        vm.stopPrank();
        handler =
            new PufferProtocolHandler(this, pool, withdrawalPool, pufferProtocol, guardiansEnclavePks, _broadcaster);

        // Set handler as a target contract for invariant test
        targetContract(address(handler));
    }

    function invariant_pufferPoolETHCanOnlyGoUp() public {
        // PufferPool's ETH balance can only grow, unless it is `provisionNode`
        if (handler.ethLeavingThePool()) {
            assertLe(address(pool).balance, handler.previousBalance(), "balance should be smaller");
        } else {
            assertGe(address(pool).balance, handler.previousBalance(), "balance should go up");
        }
    }

    // Make sure that the pufETH doesn't disappear
    function invariant_pufferProtocolBond() public {
        // Validate against ghost variable
        uint256 pufETHinProtocol = pool.balanceOf(address(pufferProtocol));
        assertEq(handler.ghost_pufETH_bond_amount(), pufETHinProtocol, "missing bond from the protocol");

        // Validate by calculating eth
        uint256 ethAmount = pool.calculatePufETHtoETHAmount(pufETHinProtocol);
        uint256 originalETHAmountDeposited = (handler.ghost_validators() * 1 ether);

        // If the eth amount is lower than the original eth deposited, it is because of the rounding down (calculation for when we pay out users)
        if (ethAmount < originalETHAmountDeposited) {
            assertApproxEqRel(
                ethAmount,
                originalETHAmountDeposited,
                0.01e18,
                "bond should be worth more than the number of validators depositing"
            );
        } else {
            assertGe(
                ethAmount,
                originalETHAmountDeposited,
                "bond should be worth more than the number of validators depositing"
            );
        }
    }

    // pufETH should always be worth more than ETH
    function invariant_pufEthToETHRate() public {
        // Exchange rate should always be bigger than 1:1, we are not supposed to be losing anything with this setup ATM
        assertTrue(pool.getPufETHtoETHExchangeRate() >= 1 ether);
    }

    function invariant_callSummary() public view {
        handler.callSummary();
    }
}
