import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import fs from "fs";

// Values for proof #1 for NoRestakingStrategy.t.sol
const valuesProf1 = [
  ["0x328809Bc894f92807417D2dAD6b7C998c1aFdac6", "0xe1ab8030737e227464912c87005a255ebf7472264e511b5bc6925d5af301e5c2", "16080000000000000"],
  ["0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e", "0x7b08d1ea016d45d5b69194738de2b0b7d134221e5e062e5f61566cf6440059d9", "16120000000000000"],
  ["0xea475d60c118d7058beF4bDd9c32bA51139a74e0", "0xb6778516d44d232c5fe78bce5c80b81bdc8966730a6b285d560f0ee5ab4ed209", "16070000000000000"],
];

// Values for proof #2 for NoRestakingStrategy.t.sol
const valuesProof2 = [
  ["0x328809Bc894f92807417D2dAD6b7C998c1aFdac6", "0xe1ab8030737e227464912c87005a255ebf7472264e511b5bc6925d5af301e5c2", "26080000000000000"],
  ["0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e", "0x7b08d1ea016d45d5b69194738de2b0b7d134221e5e062e5f61566cf6440059d9", "36120000000000000"],
  ["0xea475d60c118d7058beF4bDd9c32bA51139a74e0", "0xb6778516d44d232c5fe78bce5c80b81bdc8966730a6b285d560f0ee5ab4ed209", "46070000000000000"],
];

// (2)
const tree = StandardMerkleTree.of(values, ["address", "bytes32", "uint256"]);

// (3)
console.log('Merkle Root:', tree.root);

// (4)
fs.writeFileSync("tree.json", JSON.stringify(tree.dump()));

console.log(tree.render());

// Get proofs
for (const [i, v] of tree.entries()) {
    const proof = tree.getProof(i);
    console.log('Proof:', proof);
}