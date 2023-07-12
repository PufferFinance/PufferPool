// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import { WETH9 } from "test/mocks/WETH9.sol";

/**
 * @title DeployWeth script
 * @author Puffer finance
 * @notice Meant for deployment of WETH9 for testing
 */
contract DeployWeth is Script {
    function run() external returns (WETH9) {
        vm.startBroadcast();

        WETH9 weth = new WETH9();

        vm.stopBroadcast();

        return (weth);
    }
}