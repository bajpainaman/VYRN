// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {VyrnBridge} from "../src/VyrnBridge.sol";
import {IVyrnBridge} from "../src/IVyrnBridge.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// Deploys the bridge on L1 chain id 1 with VYRN chain id 7,
/// tokens at the addresses of vectors/wdtree.json, keys 0x1001.. (BK) and 0x2001.. (GK).
abstract contract BridgeBase is Test {
    address constant BRIDGE = 0x0B21D6e000000000000000000000000000000001;
    address constant USDC = 0x00000000000000000000000000000000000A5501;
    address constant WETH = 0x00000000000000000000000000000000000a5502;
    uint32 constant VYRN_CHAIN = 7;

    VyrnBridge bridge;
    uint256[5] bkPk;
    uint256[5] gkPk;
    address[] bks;
    address[] gks;
    address user = address(0xA11CE);
    string wdJson;

    function setUp() public virtual {
        vm.chainId(1);
        vm.warp(1_800_000_000);
        deployCodeTo("MockERC20.sol:MockERC20", USDC);
        deployCodeTo("MockERC20.sol:MockERC20", WETH);
        for (uint256 i = 0; i < 5; ++i) {
            bkPk[i] = 0x1001 + i;
            gkPk[i] = 0x2001 + i;
            bks.push(vm.addr(bkPk[i]));
            gks.push(vm.addr(gkPk[i]));
        }
        address[] memory list = new address[](2);
        list[0] = USDC;
        list[1] = WETH;
        // `new`, so that the gas report sees the bridge; VectorsTest redeploys it at BRIDGE.
        bridge = new VyrnBridge(VYRN_CHAIN, list, bks, gks);
        wdJson = vm.readFile("vectors/wdtree.json");
    }

    // ---------------------------------------------------------------- helpers

    function _deposit(address token, uint256 amount) internal returns (uint64) {
        MockERC20(token).mint(user, amount);
        vm.startPrank(user);
        MockERC20(token).approve(address(bridge), amount);
        bridge.deposit(token, amount, 1, bytes32(uint256(uint160(user))));
        vm.stopPrank();
        return bridge.depositCount();
    }

    /// 3 deposits: enough balance that the three vector withdrawals fit the 10% daily cap.
    function _fund() internal {
        _deposit(USDC, 100_000_000);
        _deposit(WETH, 10 ether);
        _deposit(USDC, 1_000_000);
    }

    function _post(uint64 no, bytes32 wdRoot, uint256 t0, uint256 t1)
        internal
        pure
        returns (IVyrnBridge.Post memory p)
    {
        uint256[] memory totals = new uint256[](2);
        totals[0] = t0;
        totals[1] = t1;
        p = IVyrnBridge.Post({
            postNo: no,
            chainId: VYRN_CHAIN,
            prevPost: bytes32(0),
            commit: keccak256(abi.encode("commit", no)),
            smtRoot: keccak256(abi.encode("smt", no)),
            depositNonce: 0,
            wdRoot: wdRoot,
            wdCount: 3,
            wdTotals: totals
        });
    }

    /// Post no with the withdrawal tree of vectors/wdtree.json.
    function _wdPost(uint64 no) internal view returns (IVyrnBridge.Post memory) {
        return _post(no, vm.parseJsonBytes32(wdJson, ".root"), 4_500_000, 250_000_000_000_000_000);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Signatures by the bridge keys whose index bit is set in mask, in index order.
    function _sigs(uint256[5] storage pks, uint256 mask, bytes32 digest)
        internal
        view
        returns (bytes[] memory out)
    {
        uint256 n;
        for (uint256 i = 0; i < 5; ++i) {
            if (mask >> i & 1 == 1) ++n;
        }
        out = new bytes[](n);
        n = 0;
        for (uint256 i = 0; i < 5; ++i) {
            if (mask >> i & 1 == 1) out[n++] = _sign(pks[i], digest);
        }
    }

    function _propose(IVyrnBridge.Post memory p, uint256 mask) internal {
        bridge.proposePost(p, _sigs(bkPk, mask, bridge.hashPost(p)));
    }

    /// expectRevert applies to the next call, so the digest is computed before it is armed.
    function _proposeExpect(IVyrnBridge.Post memory p, uint256 mask, bytes4 err) internal {
        bytes[] memory s = _sigs(bkPk, mask, bridge.hashPost(p));
        vm.expectRevert(err);
        bridge.proposePost(p, s);
    }

    function _rotateExpect(IVyrnBridge.SignerSet memory set, uint256 mask, bytes4 err) internal {
        bytes[] memory s = _sigs(bkPk, mask, bridge.hashSignerSet(set));
        vm.expectRevert(err);
        bridge.rotateSigners(set, s);
    }

    function _wd(uint256 i) internal view returns (IVyrnBridge.Withdrawal memory w, bytes32[] memory proof) {
        string memory b = string.concat(".leaves[", vm.toString(i), "]");
        w = IVyrnBridge.Withdrawal({
            wdId: uint64(vm.parseJsonUint(wdJson, string.concat(b, ".wdId"))),
            token: vm.parseJsonAddress(wdJson, string.concat(b, ".token")),
            amount: vm.parseJsonUint(wdJson, string.concat(b, ".amount")),
            recipient: vm.parseJsonAddress(wdJson, string.concat(b, ".recipient"))
        });
        proof = vm.parseJsonBytes32Array(wdJson, string.concat(b, ".proof"));
    }

    function _claim(uint64 postNo, uint256 i) internal {
        (IVyrnBridge.Withdrawal memory w, bytes32[] memory proof) = _wd(i);
        bridge.claim(postNo, w, proof);
    }

    function _acceptedAt(uint64 postNo) internal view returns (uint256) {
        (VyrnBridge.PostRec memory r,) = bridge.posts(postNo);
        return r.acceptedAt;
    }
}
