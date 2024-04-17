// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferVaultV2 } from "pufETH/PufferVaultV2.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { IPufferOracleV2 } from "puffer/interface/IPufferOracleV2.sol";

contract PufferProtocolMockUpgrade is PufferProtocol {
    function returnSomething() external pure returns (uint256) {
        return 1337;
    }

    constructor(address beacon)
        PufferProtocol(
            PufferVaultV2(payable(address(0))),
            GuardianModule(payable(address(0))),
            address(0),
            ValidatorTicket(address(0)),
            IPufferOracleV2(address(0)),
            address(0)
        )
    { }
}
