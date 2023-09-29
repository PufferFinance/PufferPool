// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";

contract PufferProtocolMockUpgrade is PufferProtocol {
    function returnSomething() external pure returns (uint256) {
        return 1337;
    }

    constructor(address beacon)
        PufferProtocol(Safe(payable(address(0))), payable(address(0)), IStrategyManager(address(0)), address(0))
    { }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
