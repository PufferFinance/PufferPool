// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

interface PufferPoolInterface {
	function registerPod(bytes[] memory raEvidences, bytes[] memory ethPks, uint256[] memory regBlockNums, bytes32 mrenclave) external returns(bool success);

    function registerCrew(bytes[] memory raEvidences, bytes[] memory ethPks, uint256[] memory regBlockNums, bytes32 mrenclave) external returns(bool success);

    function upgradeCrew(address newCrewAddress) external returns(bool success);

    function registerValidatorKey(
        bytes memory pubKey, 
        bytes[] memory pubKeyShares, 
        bytes[] memory encKeyShares, 
        bytes memory depositDataRoot, 
        bytes memory depositSignature,
        bytes[] memory podSignatures,
        bytes32 podType)
        external payable returns(bytes32 withdrawalCredentials);

	function provisionPod(
        bytes memory pubKey, 
        bytes memory depositDataRoot, 
        bytes memory depositSignature,
        bytes[] memory crewSignatures,
        bytes32 podType)
        external returns(bool success);

	function calcWithdrawalCredentials(bytes memory pubKey) external returns(address withdrawalCredentials);

}

abstract contract PufferPoolInternals is PufferPoolInterface {
	function extractEnclaveEthKeys(bytes[] memory payloads) internal virtual returns (bytes memory pubKeys);

	function decodeToEthPubkey(bytes memory enclavePayload) internal virtual pure returns (bytes memory pubKey);

    function crewAccountFactory(bytes[] memory crewEnclavePubKeys, address[] memory crewWallets, bytes32 mrenclave) internal virtual returns(address accountAddress);

    function podAccountFactory(bytes[] memory podEnclavePubKeys, address[] memory podWallets, bytes32 mrenclave) internal virtual returns(address accountAddress);

    function splitterContractFactory(bytes32 seed) internal virtual returns(address accountAddress);
}