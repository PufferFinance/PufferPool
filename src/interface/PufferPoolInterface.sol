// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

interface PufferPoolInterface {
    function registerPod(
        bytes[] memory raEvidences,
        bytes[] memory ethPks,
        uint256[] memory regBlockNums,
        bytes32 mrenclave
    ) external returns (bool success);

    function registerCrew(
        bytes[] memory raEvidences,
        bytes[] memory ethPks,
        uint256[] memory regBlockNums,
        bytes32 mrenclave
    ) external returns (bool success);

    function upgradeCrew(
        address newCrewAddress
    ) external returns (bool success);

    function registerValidatorKey(
        bytes memory pubKey,
        bytes[] memory pubKeyShares,
        bytes[] memory encKeyShares,
        bytes memory depositDataRoot,
        bytes memory depositSignature,
        bytes[] memory podSignatures,
        bytes32 podType
    ) external payable returns (bytes32 withdrawalCredentials);

    function provisionPod(
        bytes memory pubKey,
        bytes memory depositDataRoot,
        bytes memory depositSignature,
        bytes[] memory crewSignatures,
        bytes32 podType
    ) external returns (bool success);

    function approveRestakeRequest(
        address targetContract,
        bytes32 podType
    ) external payable returns (bool success);

    function calcWithdrawalCredentials(
        bytes memory pubKey
    ) external pure returns (address withdrawalCredentials);

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

    // LST related
    function mint(address recipient) external payable;

    function redeem(address recipient) external payable;

    // Contract maintanence
    function pause() external;

    function resume() external;

    function upgrade(address newContractAddr) external;

    // Setters to set parameters
    function setParamX() external;

    // Getters to get parameters
    function getParamX() external returns (uint256 X);
}
