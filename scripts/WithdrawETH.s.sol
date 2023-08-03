// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "scripts/BaseScript.s.sol";

/**
 * @title Withdraw ETH script
 * @author Puffer finance
 * @notice Calls the `withdrawETH` function on PufferPool
 * @dev Example on how to run the script
 *      If the first parameter is `0`, it will burn all of the pufETH owned by the tx broadcaster
 * 
 *      forge script scripts/WithdrawETH.s.sol:WithdrawETH --rpc-url=$EPHEMERY_RPC_URL --broadcast --sig "run(uint256, address)" -vvvv 1000000000000000000 0x5F9a7EA6A79Ef04F103bfe7BD45dA65476a5155C
 */
contract WithdrawETH is BaseScript {
    /**
     * @param pufETHAmount Is the pufETH amount to exchange for ETH
     * @param recipient is the recipient of pufETH
     */
    function run(uint256 pufETHAmount, address recipient) external broadcast {
        if (pufETHAmount == 0) {
            pufETHAmount = _pufferPool.balanceOf(_broadcaster);
        }
        _pufferPool.withdrawETH(recipient, pufETHAmount);
    }
}