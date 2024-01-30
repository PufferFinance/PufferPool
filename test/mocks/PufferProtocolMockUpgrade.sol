// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";

contract PufferProtocolMockUpgrade is PufferProtocol {
    function returnSomething() external pure returns (uint256) {
        return 1337;
    }

    constructor(address beacon)
        PufferProtocol(
            IWithdrawalPool(address(0)),
            IPufferPool(address(0)),
            ValidatorTicket(address(0)),
            GuardianModule(payable(address(0))),
            payable(address(0)),
            address(0)
        )
    { }
}
