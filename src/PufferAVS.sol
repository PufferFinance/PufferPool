// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferAVS } from "puffer/interface/IPufferAVS.sol";
import { PufferServiceManager } from "puffer/PufferServiceManager.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { ValidatorEnclaveKeyData } from "puffer/struct/ValidatorEnclaveKeyData.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";

contract PufferAVS is IPufferAVS, PufferServiceManager {
    constructor(Safe guardians, address payable treasury, IStrategyManager eigenStrategyManager)
        PufferServiceManager(guardians, treasury, eigenStrategyManager)
    { }

    function haltOperator(address operator) external { }

    function recordInitialStakeUpdate(address operator, uint32 serveUntil) external { }

    /*
    function registerEnclaveValidatorKey(ValidatorEnclaveKeyData calldata data) external {
        return super.registerEnclaveValidatorKey(data);
    }*/

    function cancelRegistration() external { }

    function recordFinalStakeUpdateRevokeSlashing(address operator, uint32 serveUntil) external { }

    function recordStakeUpdate(address operator, uint32 updateBlock, uint32 serveUntil, uint256 prevElement) external { }
}
