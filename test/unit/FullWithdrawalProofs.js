import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import fs from "fs";

const NO_RESTAKING = "0x4e4f5f52455354414b494e470000000000000000000000000000000000000000"
const EIGEN_DA = "0x454947454e5f4441000000000000000000000000000000000000000000000000"

const valuesProf1 = [
  [NO_RESTAKING, "0", "32140000000000000000", "0"],
  [EIGEN_DA, "0", "31000000000000000000", "1"],
  [NO_RESTAKING, "1", "31600000000000000000", "0"],
];

// (2)
// strategyName, validatorIndex, withdrawalAmount, wasSlashed 
const tree = StandardMerkleTree.of(valuesProf1, ["bytes32", "uint256", "uint256", "uint8"]); // (bool == uint8)

// (3)
console.log('Merkle Root:', tree.root);

// (4)
fs.writeFileSync("tree.json", JSON.stringify(tree.dump()));

// Get proofs
for (const [i, v] of tree.entries()) {
    console.log('value:', v);
    const proof = tree.getProof(i);
    console.log('Proof:', proof);
}