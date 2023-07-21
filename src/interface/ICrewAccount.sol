// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "eigenlayer/libraries/BeaconChainProofs.sol";

interface CrewAccountInterface {
    // Meant to be called in constructor
    function initialize(bytes[] memory crewEnclavePubKeys, address[] memory crewWallets) external;

    // Sets the guardian's enclaveAddress
    function setGuardianKey(address guardian, address enclaveAddress) external;

    // CrewAccount provisions ETH to a validator
    function provisionPodETH(
        address eigenPodProxy,
        bytes calldata pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external returns (bool success);

    function ejectPodForInactivity(
        address pufferServiceManager,
        address eigenPodProxy,
        uint40 validatorIndex,
        BeaconChainProofs.ValidatorFieldsAndBalanceProofs calldata proofs,
        bytes32[] calldata validatorFields,
        uint64 oracleBlockNumber
    ) external;

    function ejectPodForTheft(address pufferServiceManager, address eigenPodProxy, uint40 validatorIndex) external;
}
