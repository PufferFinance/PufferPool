// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import {Script} from "forge-std/Script.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DeployPufferPool script
 * @author Puffer finance
 * @notice Deploys UUPS upgradeable `PufferPool`.
 */
contract DeployPufferPool is Script {
    function run() external returns (PufferPool) {
        bool pkSet = vm.envOr("PRIVATE_KEY", false);

        if (pkSet) {
            uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
            vm.startBroadcast(deployerPrivateKey);
        } else {
            vm.startBroadcast();
        }

        // Deploys Puffer Pool implementation
        PufferPool poolImpl = new PufferPool();
        // Deploys Proxy contract
        ERC1967Proxy proxy = new ERC1967Proxy(address(poolImpl), "");
        // Casts Proxy to PufferPool
        PufferPool pool = PufferPool(address(proxy));
        // Initializes the Pool
        pool.initialize();

        if (!pkSet) {
            // For test environment transfer ownership to Test contract
            pool.transferOwnership(msg.sender);
        }

        vm.stopBroadcast();

        // Returns pool
        return (pool);
    }
}