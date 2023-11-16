// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocol } from "puffer/PufferProtocol.sol";

contract PufferProtocolMockUpgrade is PufferProtocol {
    function returnSomething() external pure returns (uint256) {
        return 1337;
    }

    constructor(address beacon) PufferProtocol(payable(address(0)), address(0)) { }
}
