// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

import {BridgeBase} from "./BridgeBase.sol";
import {IVyrnBridge} from "../src/IVyrnBridge.sol";
import {VyrnBridge} from "../src/VyrnBridge.sol";

/// The contract agrees with vectors/eip712.json (eth-account digests, `cast wallet sign` signatures)
/// and vectors/wdtree.json (OpenZeppelin StandardMerkleTree). None of these were computed by the contract.
contract VectorsTest is BridgeBase {
    string j;

    function setUp() public override {
        super.setUp();
        // The vectors' verifyingContract.
        address[] memory list = bridge.assets();
        deployCodeTo("VyrnBridge.sol:VyrnBridge", abi.encode(VYRN_CHAIN, list, bks, gks), BRIDGE);
        bridge = VyrnBridge(BRIDGE);
        j = vm.readFile("vectors/eip712.json");
    }

    function _v(uint256 i, string memory f) internal pure returns (string memory) {
        return string.concat(".vectors[", vm.toString(i), "].", f);
    }

    function _postAt(uint256 i) internal view returns (IVyrnBridge.Post memory p) {
        p.postNo = uint64(vm.parseJsonUint(j, _v(i, "message.postNo")));
        p.chainId = uint32(vm.parseJsonUint(j, _v(i, "message.chainId")));
        p.prevPost = vm.parseJsonBytes32(j, _v(i, "message.prevPost"));
        p.commit = vm.parseJsonBytes32(j, _v(i, "message.commit"));
        p.smtRoot = vm.parseJsonBytes32(j, _v(i, "message.smtRoot"));
        p.depositNonce = uint64(vm.parseJsonUint(j, _v(i, "message.depositNonce")));
        p.wdRoot = vm.parseJsonBytes32(j, _v(i, "message.wdRoot"));
        p.wdCount = uint32(vm.parseJsonUint(j, _v(i, "message.wdCount")));
        p.wdTotals = vm.parseJsonUintArray(j, _v(i, "message.wdTotals"));
    }

    function _sigsAt(uint256 i) internal view returns (bytes[] memory) {
        return vm.parseJsonBytesArray(j, _v(i, "signatures"));
    }

    function test_domainAndTypeHashes() public view {
        assertEq(address(bridge), vm.parseJsonAddress(j, ".domain.verifyingContract"));
        assertEq(bridge.domainSeparator(), vm.parseJsonBytes32(j, ".domainSeparator"));
        assertEq(bridge.POST_TYPEHASH(), vm.parseJsonBytes32(j, ".typeHashes.Post"));
        assertEq(bridge.UNPAUSE_TYPEHASH(), vm.parseJsonBytes32(j, ".typeHashes.Unpause"));
        assertEq(bridge.SIGNERSET_TYPEHASH(), vm.parseJsonBytes32(j, ".typeHashes.SignerSet"));
        address[] memory keys = vm.parseJsonAddressArray(j, ".bridgeKeys");
        for (uint256 i = 0; i < 5; ++i) {
            assertEq(keys[i], bks[i]);
        }
    }

    function test_postDigestsAndCastSignatures() public {
        _fund();
        for (uint256 i = 0; i < 2; ++i) {
            IVyrnBridge.Post memory p = _postAt(i);
            assertEq(bridge.hashPost(p), vm.parseJsonBytes32(j, _v(i, "digest")));
            bridge.proposePost(p, _sigsAt(i));
        }
        assertEq(bridge.lastPostNo(), 2);
        // post2.prevPost is post1's struct hash, as 09 §6.2 chains them.
        assertEq(_postAt(1).prevPost, vm.parseJsonBytes32(j, _v(0, "structHash")));
        // post1's tree is vectors/wdtree.json: every vector withdrawal claims.
        vm.warp(block.timestamp + 3_600);
        _claim(1, 0);
        _claim(1, 1);
        _claim(1, 2);
    }

    function test_unpauseAndRotationDigests() public {
        assertEq(bridge.hashUnpause(1), vm.parseJsonBytes32(j, _v(2, "digest")));
        vm.prank(gks[0]);
        bridge.pause();
        bridge.unpause(_sigsAt(2));
        IVyrnBridge.SignerSet memory s;
        s.rotationNo = uint64(vm.parseJsonUint(j, _v(3, "message.rotationNo")));
        s.bridgeKeys = vm.parseJsonAddressArray(j, _v(3, "message.bridgeKeys"));
        s.guardianKeys = vm.parseJsonAddressArray(j, _v(3, "message.guardianKeys"));
        assertEq(bridge.hashSignerSet(s), vm.parseJsonBytes32(j, _v(3, "digest")));
        bridge.rotateSigners(s, _sigsAt(3));
        (uint64 no,, bool vetoable,) = bridge.pendingRotation();
        assertEq(no, 1);
        assertFalse(vetoable); // all 5 vector signatures were given
    }

    function test_wdTreeLeafHashes() public view {
        bytes32 root = vm.parseJsonBytes32(wdJson, ".root");
        for (uint256 i = 0; i < 3; ++i) {
            (IVyrnBridge.Withdrawal memory w,) = _wd(i);
            bytes32 leaf =
                keccak256(bytes.concat(keccak256(abi.encode(w.wdId, w.token, w.amount, w.recipient))));
            assertEq(
                leaf, vm.parseJsonBytes32(wdJson, string.concat(".leaves[", vm.toString(i), "].leafHash"))
            );
        }
        assertTrue(root != bytes32(0));
    }

    function test_domainFollowsChainId() public {
        bytes32 d = bridge.domainSeparator();
        vm.chainId(11155111); // after a fork, signatures for chain 1 no longer verify
        assertTrue(bridge.domainSeparator() != d);
    }
}
