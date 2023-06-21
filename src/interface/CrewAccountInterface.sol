// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

interface CrewAccountInterface {
    // Meant to be called in constructor
    function initialize(
        bytes[] memory crewEnclavePubKeys,
        address[] memory crewWallets
    ) external;

    // CrewAccount provisions ETH to a validator
    function provisionPod(
        bytes memory pubKey,
        bytes memory depositDataRoot,
        bytes memory depositSignature,
        bytes[] memory crewSignatures,
        bytes32 podType
    ) external returns (bool success);

    function ejectPodForInactivity(
        address podAccount,
        bytes32 podType,
        bytes32 beaconStateRoot,
        uint256 validatorIndex,
        bytes[] memory crewSignatures
    ) external;

    function ejectPodForTheft(
        address podAccount,
        bytes32 podType,
        bytes32 beaconStateRoot,
        uint256 validatorIndex,
        bytes memory validatorPubKey,
        bytes[] memory crewSignatures
    ) external;
}
