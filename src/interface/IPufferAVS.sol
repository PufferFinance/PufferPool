// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { ValidatorEnclaveKeyData } from "puffer/struct/ValidatorEnclaveKeyData.sol";

interface IPufferAVS {
    /// @notice Freezes operator,
    function haltOperator(address operator) external;

    //function registerEnclaveValidatorKey(ValidatorEnclaveKeyData calldata data) external;

    //function registerValidatorKey(ValidatorKeyData calldata data) external;

    function recordInitialStakeUpdate(address operator, uint32 serveUntil) external;

    function cancelRegistration() external;

    function recordFinalStakeUpdateRevokeSlashing(address operator, uint32 serveUntil) external;

    function recordStakeUpdate(address operator, uint32 updateBlock, uint32 serveUntil, uint256 prevElement) external;
}
