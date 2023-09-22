// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferAVS } from "puffer/interface/IPufferAVS.sol";
import { PufferServiceManager } from "puffer/PufferServiceManager.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { ValidatorEnclaveKeyData } from "puffer/struct/ValidatorEnclaveKeyData.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";

contract PufferAVS is IPufferAVS, PufferServiceManager {
    ISlasher internal _slasher;

    constructor(Safe guardians, address payable treasury, IStrategyManager eigenStrategyManager, ISlasher slasher)
        PufferServiceManager(guardians, treasury, eigenStrategyManager)
    {
        _slasher = ISlasher(slasher);
    }

    function haltOperator(address operator) external onlyGuardians {
        _slasher.freezeOperator(operator);
    }

    // TODO: This is called within either registerValidatorKey function. Consider just putting this in PufferServiceManager contract?
    function recordInitialStakeUpdate(address operator, uint32 serveUntil) external onlyGuardians {
        _slasher.recordFirstStakeUpdate(operator, serveUntil);
    }

    // TODO: Check that NoOp is actually currently registered
    /**
     * @notice Called by NoOp to revoke slashing ability and end AVS obligations
     */
    function cancelRegistration() external {
        _slasher.recordLastStakeUpdateAndRevokeSlashingAbility(msg.sender, uint32(block.number));
    }

    function recordFinalStakeUpdateRevokeSlashing(address operator, uint32 serveUntil) external onlyGuardians() {
        _slasher.recordLastStakeUpdateAndRevokeSlashingAbility(operator, serveUntil);
    }

    /**
     * @dev Unused, but exposing for interface compatibility
     */
    function recordStakeUpdate(address operator, uint32 updateBlock, uint32 serveUntil, uint256 prevElement) external { }
}
