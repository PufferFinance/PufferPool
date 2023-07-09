// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "eigenlayer/interfaces/IQuorumRegistry.sol";

contract PufferAVSRegistry {

	/// @notice used for storing Operator info on each operator while registration
    mapping(address => IQuorumRegistry.Operator) public registry;

    /// @notice used for storing the list of current and past registered operators
    address[] public operatorList;

    /// @notice Returns True if the `operator` is "registered" and thus an active operator
    function operatorActive(address operator) external view returns (bool) {
    	return (registry[operator].status == IQuorumRegistry.Status.ACTIVE);
    }
}