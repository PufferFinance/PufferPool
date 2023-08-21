// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";

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

    modifier broadcast() {
        vm.startBroadcast(_deployerPrivateKey);
        _;
        vm.stopBroadcast();
    }
}