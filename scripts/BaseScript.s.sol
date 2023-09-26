// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

/**
 * @title Base Script
 * @author Puffer finance
 */
abstract contract BaseScript is Script {
    // uint256 PK = 55358659325830545179143827536745912452716312441367500916455484419538098489698; // makeAddr("pufferDeployer")
    uint256 PK = uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80);

    /**
     * @dev Deployer private key is in `PK` env variable
     */
    // uint256 _deployerPrivateKey = vm.envOr("PK", PK);
    uint256 _deployerPrivateKey = PK;
    address internal _broadcaster = vm.addr(_deployerPrivateKey);

    modifier broadcast() {
        console.log("TX broadcaster:", _broadcaster);
        vm.startBroadcast(_deployerPrivateKey);
        _;
        vm.stopBroadcast();
    }
}