// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { stdJson } from "forge-std/StdJson.sol";

/**
 * @title Deposit ETH script
 * @author Puffer Finance
 * @notice Calls the `depositETH` function on PufferPool
 * @dev Example on how to run the script
 *      forge script script/SetGuardianEnclaveMeasurements.s.sol:SetEnclaveMeasurements --rpc-url=$EPHEMERY_RPC_URL --broadcast --sig "run(bytes32,bytes32)" -vvvv 0xaa00000000000000000000000000000000000000000000000000000000000000 0xaa00000000000000000000000000000000000000000000000000000000000000
 */
contract SetEnclaveMeasurements is BaseScript {
    function run(bytes32 mrenclave, bytes32 mrsigner) external broadcast {
        string memory guardiansDeployment = vm.readFile("./output/puffer.json");

        address payable module = payable(stdJson.readAddress(guardiansDeployment, ".guardianModule"));

        GuardianModule(module).setGuardianEnclaveMeasurements({ newMrenclave: mrenclave, newMrsigner: mrsigner });
    }
}
