// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { PufferProtocol } from "../src/PufferProtocol.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { Permit } from "pufETH/structs/Permit.sol";
import { console } from "forge-std/console.sol";

/**
 * @title Rotate Guardian key and register validators
 * @author Puffer Finance
 * @dev Example on how to run the script
 *      forge script script/ProvisionValidators.s.sol:ProvisionValidators --rpc-url=$RPC_URL --broadcast --sig "run()" -vvvv
 */
contract ProvisionValidators is BaseScript {
    Permit emptyPermit;

    function run() external broadcast {
        string memory pufferDeployment = vm.readFile("./output/puffer.json");
        address payable pufferProtocol = payable(stdJson.readAddress(pufferDeployment, ".protocol"));

        for (uint256 i = 0;; ++i) {
            (, uint256 idx) = PufferProtocol(pufferProtocol).getNextValidatorToProvision();
            if (idx == type(uint256).max) {
                return;
            }

            console.log("Provisioning", idx);

            // Mock signature
            bytes memory validatorSignature = hex"a28746e085e1f08c09624501108a1853e8bfd0b4237690ec547ab0cffec8a8b6ba3844565d8a96ca029d9224ccb90ab613abd330d9143f4a1402e03cb44d1a9f00f5af6e286f82c527caa95012714278e94ee79660594e9f7fe4d48f4b75f074";

            PufferProtocol(pufferProtocol).provisionNode(new bytes[](1), validatorSignature, 1 ether);
        }
    }
}