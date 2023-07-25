// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import {UpgradeableBeacon} from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import {EigenPodManagerMock} from "eigenlayer-test/mocks/EigenPodManagerMock.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { SlasherMock } from "test/mocks/SlasherMock.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";

/**
 * @title DeployBeacon script
 * @author Puffer finance
 * @notice Deployment of Beacon for EigenPodProxy
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

        IEigenPodManager eigenPodManager;

        // If we have manager in .env use that address
        bool managerSet = vm.envOr("EIGEN_POD_MANAGER", false);
        if (!managerSet) {
            // If not, deploy mock
            eigenPodManager = new EigenPodManagerMock();
        } else {
            eigenPodManager = IEigenPodManager(vm.envAddress("EIGEN_POD_MANAGER"));
        }
        
        ISlasher slasher = new SlasherMock(IStrategyManager(address(0)), IDelegationManager(address(0)));
        EigenPodProxy eigenPodProxyImplementation = new EigenPodProxy(eigenPodManager, slasher);

        UpgradeableBeacon beacon = new UpgradeableBeacon(address(eigenPodProxyImplementation));

        vm.stopBroadcast();

        // Returns Proxy Factory & Safe Implementation
        return (eigenPodProxyImplementation, beacon);
    }
}