// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { stdJson } from "forge-std/StdJson.sol";

/**
 * @title Base Script
 * @author Puffer finance
 */
abstract contract BaseScript is Script {
    /**
     * @dev Deployer private key is in `PK` env variable
     */
    uint256 _deployerPrivateKey = vm.envUint("PK");
    address internal _broadcaster = vm.addr(_deployerPrivateKey);

    /**
     * @dev Reads the deployment file
     */
    string internal _deploymentFilePath = string(abi.encodePacked("deployments/", Strings.toString(block.chainid), "-deployment.json"));
    string internal _deploymentData = vm.readFile(_deploymentFilePath);

    /**
     * @dev PufferPool deployed on block.chainId
     */
    IPufferPool internal _pufferPool = IPufferPool(stdJson.readAddress(_deploymentData, ".PufferPool"));

    modifier broadcast() {
        vm.startBroadcast(_deployerPrivateKey);
        _;
        vm.stopBroadcast();
    }
}