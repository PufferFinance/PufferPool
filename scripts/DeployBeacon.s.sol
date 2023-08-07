// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { EigenPodManagerMock } from "eigenlayer-test/mocks/EigenPodManagerMock.sol";
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
    function run(bool useEigenPodManagerMock) external returns (EigenPodProxy, UpgradeableBeacon) {
        vm.startBroadcast();

        address eigenPodManager = address(new EigenPodManagerMock());
        if (!useEigenPodManagerMock) {
            eigenPodManager = 0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338;
        }
        
        ISlasher slasher = new SlasherMock(IStrategyManager(address(0)), IDelegationManager(address(0)));
        EigenPodProxy eigenPodProxyImplementation = new EigenPodProxy(IEigenPodManager(eigenPodManager), slasher);

        UpgradeableBeacon beacon = new UpgradeableBeacon(address(eigenPodProxyImplementation));

        vm.stopBroadcast();

        // Returns Proxy Factory & Safe Implementation
        return (eigenPodProxyImplementation, beacon);
    }
}