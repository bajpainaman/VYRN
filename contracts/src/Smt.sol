// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

import {Blake3} from "./Blake3.sol";
import {SmtEmpty} from "./SmtEmpty.sol";

/// @title The balance SMT of 09 §9.3: binary, depth 256, BLAKE3
/// @notice leaf_hash = BLAKE3(derive_key("vyrn v1 smt leaf", key ‖ encode(value)))
///         node_hash = BLAKE3(derive_key("vyrn v1 smt node", left ‖ right))
/// Bit d of a key (most significant bit of byte 0 is d = 0) picks the right child at depth d. Bit d of
/// a proof's bitmap, counted the same way, is set iff the sibling at depth d is not empty; the empty
/// sibling at depth d is E[255 - d]. Siblings are listed by increasing depth.
library Smt {
    // derive_key context keys of the two contexts, as lanes (computed by Blake3.hashChunk with
    // DERIVE_KEY_CONTEXT; vectors/smt.json checks the result end to end against Python's blake3).
    uint256 internal constant LEAF_CK_A = 0x00000000d5abc34600000000e0fbe3d900000000c6a590f6000000004a2103e4;
    uint256 internal constant LEAF_CK_B = 0x00000000a1128f86000000003053657400000000ad839b2b00000000b07ca4a7;
    uint256 internal constant NODE_CK_A = 0x00000000f05a4e6b00000000b52c2b83000000009c785a150000000053003942;
    uint256 internal constant NODE_CK_B = 0x0000000099427116000000000c41157e000000007d7eb8070000000088e54dd3;

    uint256 private constant ONE_BLOCK = Blake3.CHUNK_START | Blake3.CHUNK_END | Blake3.ROOT;

    error BadProofShape();

    /// @dev BLAKE3 of 32 bytes given as lanes, using scratch memory m.
    function _hash32(uint256 m, uint256 a, uint256 b) private pure returns (uint256, uint256) {
        Blake3.storeLanes(m, a, b);
        return Blake3.compressHalf(Blake3.IV_A, Blake3.IV_B, m, 32, ONE_BLOCK);
    }

    /// @dev node_hash in lanes.
    function _node(uint256 m, uint256 lA, uint256 lB, uint256 rA, uint256 rB)
        private
        pure
        returns (uint256, uint256)
    {
        Blake3.storeLanes(m, lA, lB);
        Blake3.storeLanes(m + 0x100, rA, rB);
        (uint256 a, uint256 b) =
            Blake3.compress(NODE_CK_A, NODE_CK_B, m, 64, ONE_BLOCK | Blake3.DERIVE_KEY_MATERIAL);
        return _hash32(m, a, b);
    }

    /// @notice BLAKE3(bytes), for leaf keys.
    function hash(bytes memory b) internal pure returns (bytes32) {
        (uint256 x, uint256 y) = Blake3.hashChunk(b, Blake3.IV_A, Blake3.IV_B, 0);
        return Blake3.fromLanes(x, y);
    }

    /// @notice leaf_hash(key, value) where `material` = key ‖ encode(value).
    function leafHash(bytes memory material) internal pure returns (bytes32) {
        (uint256 a, uint256 b) = Blake3.hashChunk(material, LEAF_CK_A, LEAF_CK_B, Blake3.DERIVE_KEY_MATERIAL);
        (a, b) = _hash32(Blake3.scratch(), a, b);
        return Blake3.fromLanes(a, b);
    }

    /// @notice node_hash(left, right).
    function nodeHash(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        (uint256 lA, uint256 lB) = Blake3.toLanes(left);
        (uint256 rA, uint256 rB) = Blake3.toLanes(right);
        (uint256 a, uint256 b) = _node(Blake3.scratch(), lA, lB, rA, rB);
        return Blake3.fromLanes(a, b);
    }

    /// @notice The root implied by a leaf hash at `key` and its proof.
    function computeRoot(bytes32 key, bytes32 leaf, bytes32 bitmap, bytes32[] calldata siblings)
        internal
        pure
        returns (bytes32)
    {
        bytes memory empty = SmtEmpty.TABLE;
        uint256 m = Blake3.scratch();
        uint256 n = siblings.length;
        (uint256 a, uint256 b) = Blake3.toLanes(leaf);
        for (uint256 i = 0; i < 256; ++i) {
            // depth d = 255 - i; its empty sibling is E[i]
            bytes32 sib;
            if ((uint256(bitmap) >> i) & 1 == 1) {
                if (n == 0) revert BadProofShape();
                sib = siblings[--n];
            } else {
                assembly ("memory-safe") {
                    sib := mload(add(add(empty, 0x20), shl(5, i)))
                }
            }
            (uint256 sA, uint256 sB) = Blake3.toLanes(sib);
            if ((uint256(key) >> i) & 1 == 0) (a, b) = _node(m, a, b, sA, sB);
            else (a, b) = _node(m, sA, sB, a, b);
        }
        if (n != 0) revert BadProofShape();
        return Blake3.fromLanes(a, b);
    }
}
