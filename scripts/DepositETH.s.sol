// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "scripts/BaseScript.s.sol";

/**
 * @title Deposit ETH script
 * @author Puffer finance
 * @notice Calls the `depositETH` function on PufferPool
 * @dev Example on how to run the script
 *      forge script scripts/DepositETH.s.sol:DepositETH --rpc-url=$EPHEMERY_RPC_URL --broadcast --sig "run(uint256, address)" -vvvv 1000000000000000000 0x5F9a7EA6A79Ef04F103bfe7BD45dA65476a5155C
 */
contract DepositETH is BaseScript {
    /**
     * @param ethAmount Is the ETH amount to convert to pufETH
     * @param recipient is the recipient of pufETH
     */
    function run(uint256 ethAmount, address recipient) external broadcast {
        _pufferPool.depositETH{value: ethAmount}(recipient);
    }
}