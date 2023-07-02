// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

interface IPufferAVSDisputeResolution {
	/// @notice Slash operator with proof of deserving slash. 
	/// @notice Should call slasher.freezeOperator with corresponding address
	function proveSlashableAction(bytes calldata proof) external;
}