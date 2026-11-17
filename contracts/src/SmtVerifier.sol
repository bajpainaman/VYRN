// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

import {Smt} from "./Smt.sol";

/// @title The 09 §9.3 balance SMT as a stateless contract
/// @notice VyrnBridge deploys one in its constructor and calls it only from escapeClaim. It is separate
/// because the BLAKE3 code and the empty-subtree table would push the bridge past the EIP-170 code size
/// limit. It has no state and no owner, so anyone (a light client, another bridge) may call it.
contract SmtVerifier {
    /// @notice BLAKE3-256 of at most 1,024 bytes.
    function hash(bytes calldata b) external pure returns (bytes32) {
        return Smt.hash(b);
    }

    /// @notice leaf_hash of material = key ‖ encode(value).
    function leafHash(bytes calldata material) external pure returns (bytes32) {
        return Smt.leafHash(material);
    }

    /// @notice The root implied by leaf hash `leaf` at `key` and the proof (bitmap, siblings).
    function computeRoot(bytes32 key, bytes32 leaf, bytes32 bitmap, bytes32[] calldata siblings)
        external
        pure
        returns (bytes32)
    {
        return Smt.computeRoot(key, leaf, bitmap, siblings);
    }

    /// @notice key and material in one call: returns computeRoot(BLAKE3(keyPre), leaf_hash(key ‖ value)).
    function rootOf(bytes calldata keyPre, bytes calldata value, bytes32 bitmap, bytes32[] calldata siblings)
        external
        pure
        returns (bytes32)
    {
        bytes32 key = Smt.hash(keyPre);
        return Smt.computeRoot(key, Smt.leafHash(bytes.concat(key, value)), bitmap, siblings);
    }
}
