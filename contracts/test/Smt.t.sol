// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Smt} from "../src/Smt.sol";
import {SmtEmpty} from "../src/SmtEmpty.sol";

contract SmtHarness {
    function computeRoot(bytes32 key, bytes32 leaf, bytes32 bitmap, bytes32[] calldata siblings)
        external
        pure
        returns (bytes32)
    {
        return Smt.computeRoot(key, leaf, bitmap, siblings);
    }
}

/// Checks the Solidity SMT against vectors/smt.json, which script/gen_smt.py computes with Python's
/// blake3 package.
contract SmtTest is Test {
    SmtHarness h = new SmtHarness();
    string json;

    function setUp() public {
        json = vm.readFile("vectors/smt.json");
    }

    function _s(string memory a, uint256 i, string memory f) internal pure returns (string memory) {
        return string.concat(".", a, "[", vm.toString(i), "].", f);
    }

    function test_emptyTable() public view {
        bytes memory t = SmtEmpty.TABLE;
        bytes32[] memory e = vm.parseJsonBytes32Array(json, ".empty");
        for (uint256 i = 0; i < 4; ++i) {
            bytes32 x;
            assembly {
                x := mload(add(add(t, 0x20), shl(5, i)))
            }
            assertEq(x, e[i]);
        }
        bytes32 last;
        assembly {
            last := mload(add(add(t, 0x20), shl(5, 255)))
        }
        assertEq(last, e[4]);
        assertEq(Smt.nodeHash(e[4], e[4]), e[5], "E[256]");
        assertEq(Smt.nodeHash(bytes32(0), bytes32(0)), vm.parseJsonBytes32(json, ".nodeHashOfZeros"));
    }

    function _check(string memory arr, uint256 n) internal view {
        bytes32 root = vm.parseJsonBytes32(json, ".root");
        for (uint256 i = 0; i < n; ++i) {
            bytes memory value = vm.parseJsonBytes(json, _s(arr, i, "value"));
            bytes32 key = vm.parseJsonBytes32(json, _s(arr, i, "key"));
            bytes32 leaf = Smt.leafHash(bytes.concat(key, value));
            assertEq(leaf, vm.parseJsonBytes32(json, _s(arr, i, "leafHash")), "leaf");
            bytes32 bm = vm.parseJsonBytes32(json, _s(arr, i, "bitmap"));
            bytes32[] memory sibs = vm.parseJsonBytes32Array(json, _s(arr, i, "siblings"));
            assertEq(h.computeRoot(key, leaf, bm, sibs), root, "root");
            // A wrong leaf gives a different root.
            assertTrue(h.computeRoot(key, keccak256(abi.encode(leaf)), bm, sibs) != root);
        }
    }

    function test_accountAndBalanceProofs() public view {
        _check("accounts", 3);
        _check("balances", 6);
    }

    function test_proof27() public view {
        bytes32 key = vm.parseJsonBytes32(json, ".balances[0].key");
        bytes32 leaf = vm.parseJsonBytes32(json, ".balances[0].leafHash");
        bytes32 bm = vm.parseJsonBytes32(json, ".proof27.bitmap");
        bytes32[] memory sibs = vm.parseJsonBytes32Array(json, ".proof27.siblings");
        assertEq(sibs.length, 27);
        assertEq(h.computeRoot(key, leaf, bm, sibs), vm.parseJsonBytes32(json, ".proof27.root"));
    }

    function test_rejectsProofShape() public {
        bytes32 key = vm.parseJsonBytes32(json, ".accounts[0].key");
        bytes32 leaf = vm.parseJsonBytes32(json, ".accounts[0].leafHash");
        bytes32 bm = vm.parseJsonBytes32(json, ".accounts[0].bitmap");
        bytes32[] memory sibs = vm.parseJsonBytes32Array(json, ".accounts[0].siblings");
        bytes32[] memory more = new bytes32[](sibs.length + 1);
        for (uint256 i = 0; i < sibs.length; ++i) {
            more[i] = sibs[i];
        }
        vm.expectRevert(Smt.BadProofShape.selector);
        h.computeRoot(key, leaf, bm, more);
        bytes32[] memory fewer = new bytes32[](sibs.length - 1);
        vm.expectRevert(Smt.BadProofShape.selector);
        h.computeRoot(key, leaf, bm, fewer);
    }
}
