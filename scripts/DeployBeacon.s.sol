// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import {UpgradeableBeacon} from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";

/**
 * @title DeployBeacon script
 * @author Puffer finance
 * @notice Dep;loyment of Beacon for EigenPodProxy
 */
contract DeployBeacon is Script {
    function run() external returns (EigenPodProxy, UpgradeableBeacon) {
        vm.startBroadcast();

        EigenPodProxy eigenPodProxyImplementation = new EigenPodProxy(payable(address(0)), payable(address(0)), address(0));

        UpgradeableBeacon beacon = new UpgradeableBeacon(address(eigenPodProxyImplementation));

        vm.stopBroadcast();

        // Returns Proxy Factory & Safe Implementation
        return (eigenPodProxyImplementation, beacon);
    }
}