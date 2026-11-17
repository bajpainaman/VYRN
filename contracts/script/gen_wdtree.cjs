// Generates vectors/wdtree.json with OpenZeppelin's StandardMerkleTree, independent of the contract.
// Run from contracts/: `npm i --prefix /tmp/oz @openzeppelin/merkle-tree@1.0.8 &&
//   NODE_PATH=/tmp/oz/node_modules node script/gen_wdtree.cjs`.
// Leaf types (uint64 wdId, address token, uint256 amount, address recipient), README §Withdrawal tree.
const fs = require("fs");
const { StandardMerkleTree } = require("@openzeppelin/merkle-tree");

const TYPES = ["uint64", "address", "uint256", "address"];
const USDC = "0x00000000000000000000000000000000000a5501";
const WETH = "0x00000000000000000000000000000000000a5502";
const values = [
  ["1", USDC, "1000000", "0x000000000000000000000000000000000000e5c1"],
  ["2", WETH, "250000000000000000", "0x000000000000000000000000000000000000e5c2"],
  ["3", USDC, "3500000", "0x000000000000000000000000000000000000e5c3"],
];
const tree = StandardMerkleTree.of(values, TYPES);
const out = {
  _source: "script/gen_wdtree.cjs with @openzeppelin/merkle-tree 1.0.8 (StandardMerkleTree)",
  types: TYPES,
  root: tree.root,
  totals: ["4500000", "250000000000000000"],
  leaves: values.map((v, i) => ({
    wdId: Number(v[0]),
    token: v[1],
    amount: v[2],
    recipient: v[3],
    leafHash: tree.leafHash(v),
    proof: tree.getProof(i),
  })),
};
fs.writeFileSync("vectors/wdtree.json", JSON.stringify(out, null, 1) + "\n");
