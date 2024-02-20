// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { PufferVaultMainnet } from "pufETH/PufferVaultMainnet.sol";

/**
 * @title Deposit ETH script
 * @author Puffer Finance
 * @notice Calls the `depositETH` function on PufferPool
 * @dev Example on how to run the script
 *      forge script script/3_DepositETH.s.sol:DepositETH --rpc-url=$EPHEMERY_RPC_URL --broadcast --sig "run(uint256)" -vvvv 1000000000000000000
 */
contract DepositETH is BaseScript {
    /**
     * @param ethAmount Is the ETH amount to convert to pufETH
     */
    function run(uint256 ethAmount) external broadcast {
        string memory pufferDeployment = vm.readFile("./output/puffer.json");
        address payable vault = payable(stdJson.readAddress(pufferDeployment, ".PufferVault"));

        PufferVaultMainnet(vault).depositETH{ value: ethAmount }(_broadcaster);
    }
}
