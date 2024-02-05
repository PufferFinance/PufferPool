// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferVaultMainnet } from "pufETH/PufferVaultMainnet.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { IPufferOracle } from "puffer/interface/IPufferOracle.sol";
import { IWETH } from "pufETH/interface/Other/IWETH.sol";

contract PufferProtocolMockUpgrade is PufferProtocol {
    function returnSomething() external pure returns (uint256) {
        return 1337;
    }

    constructor(address beacon)
        PufferProtocol(
            PufferVaultMainnet(payable(address(0))),
            IWETH(address(0)),
            GuardianModule(payable(address(0))),
            payable(address(0)),
            address(0),
            ValidatorTicket(address(0)),
            IPufferOracle(address(0))
        )
    { }
}
