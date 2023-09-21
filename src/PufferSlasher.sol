// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IPufferAVS } from "puffer/interface/IPufferAVS.sol";
import { IPufferSlasher } from "puffer/interface/IPufferSlasher.sol";

contract PufferSlasher is IPufferSlasher {
    ISlasher internal _slasher;
    IPufferPool internal _pufferPool;
    IPufferAVS internal _pufferAVS;

    constructor(address slasher, address pufferPool, address pufferAVS) {
        _slasher = ISlasher(slasher);
        _pufferPool = IPufferPool(pufferPool);
        _pufferAVS = IPufferAVS(pufferAVS);
    }

    modifier onlyGuardiansOrAVS() {
        _onlyGuardiansOrAVS();
        _;
    }

    function slash(address operator) external onlyGuardiansOrAVS {
        _slasher.freezeOperator(operator);
    }

    function _onlyGuardiansOrAVS() internal view {
        if (msg.sender != address(_pufferPool.GUARDIANS()) && msg.sender != address(_pufferAVS)) {
            revert Unauthorized();
        }
    }
}