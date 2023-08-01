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
    function run(address beacon, address safeProxyFactory, address safeImplementation) external returns (PufferPool) {
        vm.startBroadcast();

        // Deploys Puffer Pool implementation
        PufferPool poolImpl = new PufferPool(beacon);
        // Deploys Proxy contract
        ERC1967Proxy proxy = new ERC1967Proxy(address(poolImpl), "");
        // Casts Proxy to PufferPool
        PufferPool pool = PufferPool(payable(address(proxy)));
        // Initializes the Pool
        address[] memory treasuryOwners = new address[](1);
        treasuryOwners[0] = address(1234); // mock owner

        pool.initialize(safeProxyFactory, safeImplementation, treasuryOwners);

        // For test environment transfer ownership to Test contract
        pool.transferOwnership(msg.sender);

        vm.stopBroadcast();

        // Returns pool
        return (pool);
    }
}