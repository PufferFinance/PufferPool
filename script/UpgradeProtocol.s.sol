// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";

/**
 * @title Deposit ETH script
 * @author Puffer Finance
 * @notice Calls the `depositETH` function on PufferPool
 * @dev Example on how to run the script
 *      forge script script/UpgradeProtocol.s.sol:UpgradeProtocol --rpc-url=$HOLESKY_RPC_URL --broadcast
 */
contract UpgradeProtocol is BaseScript {
    function run() external broadcast {
        address payable protocolProxy = payable(0x4982C744Ef2694Af2970D3eB8a58744ed3cB1b1D);

        PufferProtocol newImplementation = new PufferProtocol({
            withdrawalPool: WithdrawalPool(payable(0x378b738c0Cd4e5B373f943b1c9951730E5a29E5b)),
            pool: PufferPool(payable(0x90Daec4Cee7e7A4E5499e9E864a1eb89Bb19b8Ed)),
            validatorTicket: ValidatorTicket(address(0)),
            guardianModule: GuardianModule(payable(0x66eb09811E1e46D60eD1421884E9FD76cbE555cA)),
            treasury: payable(0x61A44645326846F9b5d9c6f91AD27C3aD28EA390),
            moduleFactory: 0x05B9c7bc894DDB37BC6Cc42EE1D2de45782aeA80
        });

        PufferProtocol(protocolProxy).upgradeToAndCall(address(newImplementation), "");
    }
}
