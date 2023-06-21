// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "src/interface/PufferPoolInterface.sol";

abstract contract PufferPoolBase is PufferPoolInterface {
    // Pool parameters
    bytes32 CREW_MRENCLAVE;
    uint256 remoteAttestationFreshnessThreshold;
    uint256 crewSize;
    uint256 crewThreshold;
    uint256 crewKeyRotationInterval;

    // Pool state
    struct Pod {
        address account;
    }
    mapping(bytes32 => mapping(address => Pod)) public pods;

    function extractEnclaveEthKeys(
        bytes[] memory payloads
    ) internal virtual returns (bytes[] memory pubKeys);

    function decodeToEthPubkey(
        bytes memory enclavePayload
    ) internal pure virtual returns (bytes memory pubKey);

    function crewAccountFactory(
        bytes[] memory crewEnclavePubKeys,
        address[] memory crewWallets,
        bytes32 mrenclave
    ) internal virtual returns (address accountAddress);

    function podAccountFactory(
        bytes[] memory podEnclavePubKeys,
        address[] memory podWallets,
        bytes32 mrenclave
    ) internal virtual returns (address accountAddress);

    function splitterContractFactory(
        bytes32 seed
    ) internal virtual returns (address contractAddress);
}
