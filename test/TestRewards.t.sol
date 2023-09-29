// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { MerkleProof } from "openzeppelin/utils/cryptography/MerkleProof.sol";

contract MerkleProofVerifier {
    bytes32 public merkleRoot;

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    function verifyProof(
        address account,
        bytes memory avsAddress,
        bytes[] memory validator_pubkeys, // Using bytes to represent validator pubkeys for flexibility
        uint256 consensus_rewards_eth,
        uint256 commission_dividend,
        uint256 commission_divisor,
        bytes32[] memory proof
    ) public view returns (bytes32[] memory, bytes32, bytes32) { //(bool) {
        // Construct the leaf from the account, validator pubkeys, and the provided data
        bytes32 leaf = keccak256(abi.encodePacked(bytes("TODO: avsAddress"), concatValidatorPubkeys(validator_pubkeys), consensus_rewards_eth, commission_dividend, commission_divisor));

        return (proof, merkleRoot, leaf);
        // Verify the proof against the merkle root
        //return MerkleProof.verify(proof, merkleRoot, leaf);
    }

    // Helper function to concatenate validator pubkeys into a single bytes
    function concatValidatorPubkeys(bytes[] memory validator_pubkeys) internal pure returns (bytes memory) {
        bytes memory allPubkeys = "";
        for (uint i = 0; i < validator_pubkeys.length; i++) {
            allPubkeys = abi.encodePacked(allPubkeys, validator_pubkeys[i]);
        }
        return allPubkeys;
    }
}