// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import {UpgradeableBeacon} from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";

/**
 * @title DeployBeacon script
 * @author Puffer finance
 * @notice Dep;loyment of Beacon for EigenPodProxy
 */
contract DeployBeacon is Script {
    function run() external returns (EigenPodProxy, UpgradeableBeacon) {
        bool pkSet = vm.envOr("PRIVATE_KEY", false);

        if (pkSet) {
            uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
            vm.startBroadcast(deployerPrivateKey);
        } else {
            vm.startBroadcast();
        }

        // TODO: deploy mock?
        IEigenPodManager eigenPodManager = IEigenPodManager(vm.envOr("EIGEN_POD_MANAGER", address(5555)));

        EigenPodProxy eigenPodProxyImplementation = new EigenPodProxy(eigenPodManager);

        UpgradeableBeacon beacon = new UpgradeableBeacon(address(eigenPodProxyImplementation));

        vm.stopBroadcast();

        // Returns Proxy Factory & Safe Implementation
        return (eigenPodProxyImplementation, beacon);
    }
}