// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferModuleManager } from "puffer/PufferModuleManager.sol";
import { UUPSUpgradeable } from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * forge script script/DeployPufferModuleManagerImplementation.s.sol:DeployPufferModuleManagerImplementation --rpc-url=$RPC_URL --private-key $PK
 */
contract DeployPufferModuleManagerImplementation is Script {
    function run() public {
        require(block.chainid == 17000, "This script is only for Puffer Holesky testnet");

        vm.startBroadcast();
        PufferModuleManager impl = new PufferModuleManager({
            pufferModuleBeacon: 0x5B81A4579f466fB17af4d8CC0ED51256b94c61D4,
            restakingOperatorBeacon: 0xa7DC88c059F57ADcE41070cEfEFd31F74649a261,
            pufferProtocol: 0x705E27D6A6A0c77081D32C07DbDE5A1E139D3F14
        });

        UUPSUpgradeable(payable(0xe4695ab93163F91665Ce5b96527408336f070a71)).upgradeToAndCall(address(impl), "");
    }
}
