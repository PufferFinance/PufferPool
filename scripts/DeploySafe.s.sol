// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";


/**
 * @title DeploySafe script
 * @author Puffer finance
 * @notice Deployment of {Safe} for testing
 */
contract DeploySafe is Script {
    function run() external returns (SafeProxyFactory, Safe) {
        vm.startBroadcast();

        SafeProxyFactory proxyFactory = new SafeProxyFactory();

        Safe safeImplementtion = new Safe();

        vm.stopBroadcast();

        // Returns Proxy Factory & Safe Implementation
        return (proxyFactory, safeImplementtion);
    }
}