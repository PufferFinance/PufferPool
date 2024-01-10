// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";

/**
 * @title Deposit ETH script
 * @author Puffer Finance
 * @notice Calls the `depositETH` function on PufferPool
 * @dev Example on how to run the script
 *      PK=... forge script script/UpgradeProtocol.s.sol:UpgradeProtocol --rpc-url=$HOLESKY_RPC_URL --broadcast
 */
contract UpgradeProtocol is BaseScript {
    function run() external broadcast {
        address payable protocolProxy = payable(0x773559Ee80eDE685FBBd5F0Ebd60608DF51b777D);

        PufferProtocol newImplementation = new PufferProtocol({
            withdrawalPool: WithdrawalPool(payable(0xDAb95f41709473d55EBF7c3b5873b96149A14353)),
            pool: PufferPool(payable(0xfE7e307d24cB0953b4b5A71E780d6f622525638c)),
            guardianModule: GuardianModule(payable(0xd4c8730F555F9E9d969BC37280805104c1B039A1)),
            treasury: payable(0x61A44645326846F9b5d9c6f91AD27C3aD28EA390),
            moduleFactory: 0x5cd853e676BC218Ec78e4CB904b7dF58db50b8e4
        });

        PufferProtocol(protocolProxy).upgradeToAndCall(address(newImplementation), "");
    }
}
