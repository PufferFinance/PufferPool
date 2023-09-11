// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { Script } from "forge-std/Script.sol";
import { EigenPodManagerMock } from "eigenlayer-test/mocks/EigenPodManagerMock.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";
import { BaseScript } from "scripts/BaseScript.s.sol";


contract CustomJSONBuilder {
    string[] public keys;

    constructor(string[] memory _keys) {
        keys = _keys;
    }

    function buildJSON(string[] memory values) public view returns (string memory) {
        require(values.length == keys.length);
        string memory json = "";
        for (uint256 i = 0; i < keys.length; i++) {
            json = string(abi.encodePacked(json, keys[i], values[i]));
        }
        return string(abi.encodePacked("{", json, '"}'));
    }
}

/**
 * @title DeployPuffer
 * @author Puffer finance
 * @notice Deploys PufferPool Contracts
 * @dev    
 * 
 * 
 *         NOTE: 
 * 
 *         If you ran the deployment script, but did not `--broadcast` the transaction, it will still update your local chainId-deployment.json file.
 *         Other scripts will fail because addresses will be updated in deployments file, but the deployment never happened.
 * 
 * 
 *         forge script scripts/DeployPuffer.s.sol:DeployPuffer -vvvv --rpc-url=$EPHEMERY_RPC_URL --broadcast
 */
contract DeployPuffer is BaseScript {   
    function run() broadcast public {
        // If we don't have these ENV variables, deploy mocks
        address eigenPodProxyBeaconOwner = _broadcaster;
        address eigenPodManager = vm.envOr("EIGEN_POD_MANAGER", address(new EigenPodManagerMock()));
        address eigenSlasher = vm.envOr("EIGEN_SLASHER", address(0));
        address safeProxy = vm.envOr("SAFE_PROXY_ADDRESS", address(new SafeProxyFactory()));
        address safeImplementation = vm.envOr("SAFE_IMPLEMENTATION_ADDRESS", address(new Safe()));
        
        // Treasury is a {Safe} multisig with 1/1 
        address[] memory treasuryOwners = new address[](1);
        treasuryOwners[0] = _broadcaster; // mock owner

        // EigenPodProxy is using Upgradeable Beacon pattern
        // To do that, we are deploying Implementation contract and upgradeable beacon
        // The beacon Owner is the deployer
        EigenPodProxy eigenPodProxyImplementation = new EigenPodProxy(IEigenPodManager(eigenPodManager), ISlasher(eigenSlasher));
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(eigenPodProxyImplementation));

        // Transfer Beacon ownership to Beacon Owner - Should be a multisig that has the power to upgrade 
        beacon.transferOwnership(eigenPodProxyBeaconOwner);


        // Deploys Puffer Pool implementation
        PufferPool poolImpl = new PufferPool(address(beacon));
        // Deploys Proxy contract
        ERC1967Proxy proxy = new ERC1967Proxy(address(poolImpl), "");
        // Casts Proxy to PufferPool
        PufferPool pool = PufferPool(payable(address(proxy)));

        // Initialize the Pool
        pool.initialize({safeProxyFactory: safeProxy, safeImplementation: safeImplementation, treasuryOwners: treasuryOwners});

        // Write JSON to deployments folder
        string[] memory keys = new string[](4);
        keys[0] = '"EigenPodProxyImplementation":"';
        keys[1] = '","PoolImplementation":"';
        keys[2] = '","EigenPodProxyBeacon":"';
        keys[3] = '","PufferPool":"';

        string[] memory values = new string[](4);
        values[0] = Strings.toHexString(address(eigenPodProxyImplementation));
        values[1] = Strings.toHexString((address(poolImpl)));
        values[2] = Strings.toHexString((address(beacon)));
        values[3] = Strings.toHexString((address(pool)));

        CustomJSONBuilder jsonBuilder = new CustomJSONBuilder(keys);
        string memory json = jsonBuilder.buildJSON(values);

        // Write deployment to deployments/${chainid}-deployment.json
        vm.writeJson(json, string(abi.encodePacked("deployments/", Strings.toString(block.chainid), "-deployment.json")));
    }
}