// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

interface PodAccountInterface {
    // Meant to be called in constructor
    function initialize(
        bytes[] memory podEnclavePubKeys,
        address[] memory podWallets,
        bytes32 podType
    ) external;

    // PodAccount posts a new validator key, required metadata, and their bond
    function registerValidatorKey(
        bytes memory pubKey,
        bytes[] memory pubKeyShares,
        bytes[] memory encKeyShares,
        bytes memory depositDataRoot,
        bytes memory depositSignature,
        bytes[] memory podSignatures
    ) external payable returns (bytes32 withdrawalCredentials);

    // PodAccount can opt-in to restake at target contract
    function restake(
        address targetContract
    ) external payable returns (bool success);

    // PodAccount can post data to the target contract (e.g., stateroot to rollup bridge contract)
    function postToRestakingService(
        address targetContract,
        bytes memory payload,
        bytes[] memory podSignatures
    ) external;

    function withdraw(address targetContract, address balanceReceiver) external;

    function skim(address targetContract, address balanceReceiver) external;
}
