// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "eigenlayer/interfaces/IQuorumRegistry.sol";
// import "eigenlayer/middleware/RegistryBase.sol";
// import "./interface/IPufferAVSRegistry.sol";

// contract PufferAVSRegistry is RegistryBase, IPufferAVSRegistry {
//     constructor(IStrategyManager _strategyManager, IServiceManager _serviceManager, uint8 _NUMBER_OF_QUORUMS)
//         RegistryBase(_strategyManager, _serviceManager, _NUMBER_OF_QUORUMS)
//     { }

//     /// @notice Returns True if the `operator` is "registered" and thus an active operator
//     function operatorActive(address operator) external view returns (bool) {
//         return (registry[operator].status == IQuorumRegistry.Status.ACTIVE);
//     }

//     function register(address operator, uint8 operatorType, bytes32 pubkeyHash) external {
//         OperatorStake memory _operatorStake = _registrationStakeEvaluation(operator, operatorType);
//         _addRegistrant(operator, pubkeyHash, _operatorStake);
//     }

//     function deregister(address operator, uint32 index) external {
//         _deregistrationCheck(operator, index);
//         bytes32 pubkeyHash = registry[operator].pubkeyHash;
//         _removeOperator(operator, pubkeyHash, index);
//     }
// }
