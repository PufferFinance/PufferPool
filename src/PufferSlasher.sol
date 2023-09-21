// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { IPufferAVS } from "puffer/interface/IPufferAVS.sol";
import { IPufferSlasher } from "puffer/interface/IPufferSlasher.sol";
import { IPufferServiceManager } from "puffer/interface/IPufferServiceManager.sol";

contract PufferSlasher is IPufferSlasher {
    ISlasher internal _slasher;
    IPufferServiceManager _pufferServiceManager;
    IPufferAVS internal _pufferAVS;

    constructor(address slasher, address pufferServiceManager, address pufferAVS) {
        _slasher = ISlasher(slasher);
        _pufferServiceManager = IPufferServiceManager(pufferServiceManager);
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
        if (msg.sender != address(_pufferServiceManager.getGuardianModule()) && msg.sender != address(_pufferAVS)) {
            revert Unauthorized();
        }
    }
}
