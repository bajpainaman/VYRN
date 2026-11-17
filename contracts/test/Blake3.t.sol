// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Blake3} from "../src/Blake3.sol";

/// Checks the Solidity BLAKE3 against the official vectors (tests/golden/blake3_test_vectors.json),
/// copied for inputs of at most one chunk into vectors/blake3.json by script/gen_vectors.py.
contract Blake3Test is Test {
    struct Case {
        bytes32 deriveKey; // fields in alphabetical order, as vm.parseJson decodes them
        bytes32 hash;
        uint256 inputLen;
        bytes32 keyedHash;
    }

    function input(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            b[i] = bytes1(uint8(i % 251));
        }
    }

    function test_officialVectors() public view {
        string memory json = vm.readFile("vectors/blake3.json");
        Case[] memory cases = abi.decode(vm.parseJson(json, ".cases"), (Case[]));
        bytes memory key = bytes(vm.parseJsonString(json, ".key"));
        bytes memory ctx = bytes(vm.parseJsonString(json, ".context"));
        assertEq(cases.length, 17);
        (uint256 kA, uint256 kB) = Blake3.toLanes(bytes32(key));
        (uint256 cA, uint256 cB) = Blake3.hashChunk(ctx, Blake3.IV_A, Blake3.IV_B, Blake3.DERIVE_KEY_CONTEXT);
        for (uint256 i = 0; i < cases.length; ++i) {
            bytes memory m = input(cases[i].inputLen);
            (uint256 a, uint256 b) = Blake3.hashChunk(m, Blake3.IV_A, Blake3.IV_B, 0);
            assertEq(Blake3.fromLanes(a, b), cases[i].hash, "hash");
            (a, b) = Blake3.hashChunk(m, kA, kB, Blake3.KEYED_HASH);
            assertEq(Blake3.fromLanes(a, b), cases[i].keyedHash, "keyed_hash");
            (a, b) = Blake3.hashChunk(m, cA, cB, Blake3.DERIVE_KEY_MATERIAL);
            assertEq(Blake3.fromLanes(a, b), cases[i].deriveKey, "derive_key");
        }
    }

    function testFuzz_lanesRoundTrip(bytes32 h) public pure {
        (uint256 a, uint256 b) = Blake3.toLanes(h);
        assertEq(Blake3.fromLanes(a, b), h);
    }
}
