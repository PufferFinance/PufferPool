// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { TestBase } from "../TestBase.t.sol";
import { TestHelper } from "../helpers/TestHelper.sol";

contract MerkleProofVerifier {
    bytes32 public merkleRoot;

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    function verifyProof(address account, uint256 rewards_eth_wei, bytes32[] memory proof) public view returns (bool) {
        // Construct the leaf from the account address and rewards
        bytes32 leaf = keccak256(abi.encode(account, rewards_eth_wei));

        // Verify the proof against the merkle root
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }

    function checkProof(bytes32[] memory proof, bytes32 leaf) public view returns (bool) {
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }
}

contract MerkleProofVerifierTest is TestHelper, TestBase {
    function setUp() public override {
        super.setUp();
    }

    function testRewards() public {
        string memory file = "test/data/proof_of_rewards.json";
        string memory fileData = vm.readFile(file);

        bytes32 merkleRoot = bytes32(vm.parseJson(fileData, ".merkle_root"));
        MerkleProofVerifier verifier = new MerkleProofVerifier(merkleRoot);
        assertTrue(address(verifier) != address(0));

        address validatorAddress = address(0x0000000000000000000000000000000000000003);
        assertTrue(validatorAddress == 0x0000000000000000000000000000000000000003);

        uint256 rewards = vm.parseJsonUint(
            fileData,
            string(abi.encodePacked(".merkle_proofs.", "0000000000000000000000000000000000000003", ".rewards_eth_wei"))
        );
        assertTrue(rewards == 300);
        bytes32[] memory proof = vm.parseJsonBytes32Array(
            fileData,
            string(abi.encodePacked(".merkle_proofs.", "0000000000000000000000000000000000000003", ".merkle_proof"))
        );

        assertTrue(verifier.verifyProof(validatorAddress, rewards, proof));
    }
}
