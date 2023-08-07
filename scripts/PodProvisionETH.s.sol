// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { NewBaseScript } from "scripts/NewBaseScript.s.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";

/**
 * @title Deposit ETH script
 * @author Puffer finance
 * @notice Calls the `depositETH` function on PufferPool
 * @dev Example on how to run the script
 *      forge script scripts/ProvisionPodETH.s.sol:ProvisionPodETH --rpc-url=$EPHEMERY_RPC_URL --broadcast -vvvv --sig "run(address,bytes,bytes,bytes32)" 0xb6cB8FBE0FE546Cf2ECcFFf334E2a09FdBdcE036 0xa091f34f8e90ce7eb0f2ca31a3f12e98dbbdffcae36da273d2fe701b3b14d83a492a4704c0ac4a550308faf0eac6384e 0x 0x
 */
contract PodProvisionETH is NewBaseScript {

    /**
     * @param eigenPodProxy Is the EigenPodProxy address
     */
    function run(address pool, address eigenPodProxy, bytes calldata pubKey, bytes calldata signature, bytes32 depositRoot) external broadcast {
        IPufferPool(pool).provisionPodETH(eigenPodProxy, pubKey, signature, depositRoot);
    }
}