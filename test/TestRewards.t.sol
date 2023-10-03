// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleProofVerifier {
    bytes32 public merkleRoot;

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    function verifyProof(
        address account,
        uint256 rewards_eth_wei,
        bytes32[] memory proof
    ) public view returns (bool) { 
        // Construct the leaf from the account address and rewards
        bytes32 leaf = keccak256(abi.encode(account, rewards_eth_wei));

        // Verify the proof against the merkle root
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }

    function checkProof(
        bytes32[] memory proof,
        bytes32 leaf
    ) public view returns (bool)
    {
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }
}