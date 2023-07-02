// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

interface IPufferAVS {
	/// @notice Freezes operator, 
	function haltOperator(address operator) external;

	function recordInitialStakeUpdate(address operator, uint32 serveUntil) external;

	function recordFinalStakeUpdateRevokeSlashing(address operator, uint33 serveUntil) external;

	function recordStakeUpdate(address operator, uint32 updateBlock, uint32 serveUntil, uint256 prevElement) external;
}