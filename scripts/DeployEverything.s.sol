// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import {Script} from "forge-std/Script.sol";
import {BaseScript} from "scripts/BaseScript.s.sol";
import {SafeProxyFactory} from "safe-contracts/proxies/SafeProxyFactory.sol";
import {Safe} from "safe-contracts/Safe.sol";
import {IPufferPool} from "puffer/interface/IPufferPool.sol";
import {BeaconProxy} from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import {UpgradeableBeacon} from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import {PufferPool} from "puffer/PufferPool.sol";
import {Test} from "forge-std/Test.sol";
import {DeploySafe} from "scripts/DeploySafe.s.sol";
import {DeployPufferPool} from "scripts/DeployPufferPool.s.sol";
import {Strings} from "openzeppelin/utils/Strings.sol";
import {CustomJSONBuilder} from "scripts/DeployPuffer.s.sol";
import {IEigenPodManager} from "eigenlayer/interfaces/IEigenPodManager.sol";
import {EigenPodManagerMock} from "eigenlayer-test/mocks/EigenPodManagerMock.sol";
import {ISlasher} from "eigenlayer/interfaces/ISlasher.sol";
import {SlasherMock} from "test/mocks/SlasherMock.sol";
import {IStrategyManager} from "eigenlayer/interfaces/IStrategyManager.sol";
import {IDelegationManager} from "eigenlayer/interfaces/IDelegationManager.sol";
import {ERC1967Proxy} from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/console.sol";
import "forge-std/StdJson.sol";

using stdJson for string;

// Commandline argument will give path to ephemery simulation dir
// Example script call (Assumes `PK` environment variable is set to eth private key):
// forge script ./DeployEverything.s.sol:DeployEverything ./simulation/ephemery-sim-2 --sig 'run(string)' --rpc-url 'https://otter.bordel.wtf/erigon' --broadcast
contract DeployEverything is BaseScript {
    function run(string calldata simulationDir, address slasherAddress, address eigenPodManager) external broadcast {
        console.log("Running DeployEverything");

        ISlasher slasher = ISlasher(slasherAddress);
        
        EigenPodProxy eigenPodProxyImplementation = new EigenPodProxy(
            IEigenPodManager(eigenPodManager),
            slasher
        );

        UpgradeableBeacon beacon = new UpgradeableBeacon(
            address(eigenPodProxyImplementation)
        );
        beacon.transferOwnership(_broadcaster);

        // begin DeploySafe
        SafeProxyFactory proxyFactory = new SafeProxyFactory();

        Safe safeImplementation = new Safe();

        // Deploys Puffer Pool implementation
        PufferPool poolImpl = new PufferPool(address(beacon));
        // Deploys Proxy contract
        ERC1967Proxy proxy = new ERC1967Proxy(address(poolImpl), "");
        // Casts Proxy to PufferPool
        PufferPool pool = PufferPool(payable(address(proxy)));
        // Initializes the Pool
        address[] memory treasuryOwners = new address[](1);
        treasuryOwners[0] = address(_broadcaster); // mock owner

        pool.initialize({
            safeProxyFactory: address(proxyFactory),
            safeImplementation: address(safeImplementation),
            treasuryOwners: treasuryOwners
        });

        // For test environment transfer ownership to Test contract
        pool.transferOwnership(_broadcaster);

		console.log(address(pool));

		// Write the PufferPool address to be easily consumed by calling bash script
		vm.writeFile(string.concat(simulationDir, "/PufferPool-address"), Strings.toHexString(address(pool)));
    }
}
