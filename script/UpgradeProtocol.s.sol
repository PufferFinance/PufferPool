// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferVaultMainnet } from "pufETH/PufferVaultMainnet.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { IPufferOracle } from "puffer/interface/IPufferOracle.sol";
import { IWETH } from "pufETH/interface/Other/IWETH.sol";

/**
 * @title Deposit ETH script
 * @author Puffer Finance
 * @notice Calls the `depositETH` function on PufferPool
 * @dev Example on how to run the script
 *      forge script script/UpgradeProtocol.s.sol:UpgradeProtocol --rpc-url=$HOLESKY_RPC_URL --broadcast
 */
contract UpgradeProtocol is BaseScript {
    function run() external broadcast {
        address payable protocolProxy = payable(0x773559Ee80eDE685FBBd5F0Ebd60608DF51b777D);

        PufferProtocol newImplementation = new PufferProtocol({
            pufferVault: PufferVaultMainnet(payable(address(0))),
            validatorTicket: ValidatorTicket((address(0))),
            weth: IWETH(address(0)),
            guardianModule: GuardianModule(payable(0xd4c8730F555F9E9d969BC37280805104c1B039A1)),
            treasury: payable(0x61A44645326846F9b5d9c6f91AD27C3aD28EA390),
            moduleFactory: 0x5cd853e676BC218Ec78e4CB904b7dF58db50b8e4,
            oracle: IPufferOracle(address(0))
        });

        PufferProtocol(protocolProxy).upgradeToAndCall(address(newImplementation), "");
    }
}
