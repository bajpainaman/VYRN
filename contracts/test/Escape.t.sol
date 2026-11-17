// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

import {BridgeBase} from "./BridgeBase.sol";
import {IVyrnBridge} from "../src/IVyrnBridge.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// Escape mode (09 §6.6) and the L1 side of censorship resistance (09 §7), against vectors/smt.json.
contract EscapeTest is BridgeBase {
    string smt;

    function setUp() public override {
        super.setUp();
        smt = vm.readFile("vectors/smt.json");
    }

    /// Post 1 checkpoints the escape27 root with depositNonce 2; deposit 3 is after it.
    function _escapeSetup() internal {
        _deposit(USDC, 5_000_000_000_000);
        _deposit(WETH, 1 ether);
        _deposit(USDC, 7);
        IVyrnBridge.Post memory p = _wdPost(1);
        p.smtRoot = vm.parseJsonBytes32(smt, ".escape27.root");
        p.depositNonce = 2;
        _propose(p, 0x0f);
    }

    function _leaves()
        internal
        view
        returns (
            IVyrnBridge.AccountLeaf memory a,
            IVyrnBridge.BalanceLeaf memory l,
            IVyrnBridge.SmtProof memory ap,
            IVyrnBridge.SmtProof memory bp
        )
    {
        a = IVyrnBridge.AccountLeaf({
            account: uint32(vm.parseJsonUint(smt, ".accounts[0].account")),
            ownerKind: uint8(vm.parseJsonUint(smt, ".accounts[0].ownerKind")),
            owner: vm.parseJsonBytes32(smt, ".accounts[0].owner"),
            nonce: uint64(vm.parseJsonUint(smt, ".accounts[0].nonce")),
            exitAddress: vm.parseJsonAddress(smt, ".accounts[0].exitAddress")
        });
        l = IVyrnBridge.BalanceLeaf({
            account: uint32(vm.parseJsonUint(smt, ".balances[0].account")),
            asset: uint16(vm.parseJsonUint(smt, ".balances[0].asset")),
            free: uint128(vm.parseJsonUint(smt, ".balances[0].free")),
            allocSum: uint128(vm.parseJsonUint(smt, ".balances[0].allocSum")),
            transit: uint128(vm.parseJsonUint(smt, ".balances[0].transit")),
            pendingUnposted: uint128(vm.parseJsonUint(smt, ".balances[0].pendingUnposted")),
            pendingPosted: uint128(vm.parseJsonUint(smt, ".balances[0].pendingPosted"))
        });
        ap = IVyrnBridge.SmtProof(
            vm.parseJsonBytes32(smt, ".escape27.account.bitmap"),
            vm.parseJsonBytes32Array(smt, ".escape27.account.siblings")
        );
        bp = IVyrnBridge.SmtProof(
            vm.parseJsonBytes32(smt, ".escape27.balance.bitmap"),
            vm.parseJsonBytes32Array(smt, ".escape27.balance.siblings")
        );
    }

    function test_enterEscape_boundary() public {
        _escapeSetup();
        uint256 t = _acceptedAt(1);
        vm.warp(t + 1_209_599);
        vm.expectRevert(IVyrnBridge.EscapeNotDue.selector);
        bridge.enterEscape();
        vm.warp(t + 1_209_600);
        bridge.enterEscape();
        assertTrue(bridge.escape() && bridge.escapeResolved());
        assertEq(bridge.escapePostNo(), 1);
        assertEq(bridge.escapeDepositNonce(), 2);
        vm.expectRevert(IVyrnBridge.InEscape.selector);
        bridge.enterEscape();
        vm.expectRevert(IVyrnBridge.InEscape.selector);
        bridge.deposit(USDC, 1, 1, bytes32(uint256(1)));
        _proposeExpect(_wdPost(2), 0x0f, IVyrnBridge.InEscape.selector);
        vm.prank(gks[0]);
        vm.expectRevert(IVyrnBridge.InEscape.selector);
        bridge.pause();
    }

    /// B-CHN-4: escapeClaim with an account proof and a balance proof of 27 non-empty siblings each.
    function test_escapeClaim_paysLeafToExitAddress() public {
        _escapeSetup();
        (
            IVyrnBridge.AccountLeaf memory a,
            IVyrnBridge.BalanceLeaf memory l,
            IVyrnBridge.SmtProof memory ap,
            IVyrnBridge.SmtProof memory bp
        ) = _leaves();
        assertEq(ap.siblings.length, 27);
        assertEq(bp.siblings.length, 27);
        vm.expectRevert(IVyrnBridge.NotInEscape.selector);
        bridge.escapeClaim(a, l, ap, bp);
        vm.warp(block.timestamp + 14 days);
        bridge.enterEscape();
        uint256 g = gasleft();
        bridge.escapeClaim(a, l, ap, bp);
        emit log_named_uint("escapeClaim gas (27 + 27 siblings)", g - gasleft());
        uint256 expected = uint256(l.free) + l.allocSum + l.transit + l.pendingUnposted; // pendingPosted excluded
        assertEq(MockERC20(USDC).balanceOf(a.exitAddress), expected);
        vm.expectRevert(IVyrnBridge.AlreadyClaimed.selector);
        bridge.escapeClaim(a, l, ap, bp);
    }

    function test_escapeClaim_rejectsForgedLeaves() public {
        _escapeSetup();
        vm.warp(block.timestamp + 14 days);
        bridge.enterEscape();
        (
            IVyrnBridge.AccountLeaf memory a,
            IVyrnBridge.BalanceLeaf memory l,
            IVyrnBridge.SmtProof memory ap,
            IVyrnBridge.SmtProof memory bp
        ) = _leaves();
        IVyrnBridge.BalanceLeaf memory l2 = l;
        l2.free += 1;
        vm.expectRevert(IVyrnBridge.BadProof.selector);
        bridge.escapeClaim(a, l2, ap, bp);
        l2 = l;
        l2.pendingPosted = 0; // a field that is not paid still binds the leaf
        vm.expectRevert(IVyrnBridge.BadProof.selector);
        bridge.escapeClaim(a, l2, ap, bp);
        IVyrnBridge.AccountLeaf memory a2 = a;
        a2.exitAddress = address(0xbad);
        vm.expectRevert(IVyrnBridge.BadProof.selector);
        bridge.escapeClaim(a2, l, ap, bp);
        vm.expectRevert(IVyrnBridge.BadProof.selector);
        bridge.escapeClaim(a, l, bp, ap); // proofs swapped
    }

    function test_refundDeposit_onlyAboveEscapeNonce() public {
        _escapeSetup();
        vm.expectRevert(IVyrnBridge.NotInEscape.selector);
        bridge.refundDeposit(3);
        vm.warp(block.timestamp + 14 days);
        bridge.enterEscape();
        vm.expectRevert(IVyrnBridge.NotRefundable.selector);
        bridge.refundDeposit(2);
        vm.expectRevert(IVyrnBridge.NotRefundable.selector);
        bridge.refundDeposit(4);
        uint256 before = MockERC20(USDC).balanceOf(user);
        bridge.refundDeposit(3);
        assertEq(MockERC20(USDC).balanceOf(user) - before, 7);
        vm.expectRevert(IVyrnBridge.NotRefundable.selector);
        bridge.refundDeposit(3);
    }

    function test_escape_skipsVetoedPostsAndKeepsClaims() public {
        _escapeSetup();
        vm.warp(block.timestamp + 3_600);
        IVyrnBridge.Post memory p2 = _wdPost(2);
        p2.depositNonce = 3;
        _propose(p2, 0x0f);
        vm.prank(gks[0]);
        bridge.veto(2);
        vm.prank(gks[0]);
        bridge.pause(); // a pause does not block exits once escape starts
        vm.warp(_acceptedAt(2) + 14 days);
        bridge.enterEscape();
        assertEq(bridge.escapePostNo(), 1); // post 2 is vetoed
        _claim(1, 0); // withdrawals in accepted posts stay claimable
        bridge.refundDeposit(3);
    }

    function test_escape_withoutAnyPostRefundsEverything() public {
        _deposit(USDC, 11);
        vm.warp(block.timestamp + 14 days);
        bridge.enterEscape();
        assertEq(bridge.escapePostNo(), 0);
        (
            IVyrnBridge.AccountLeaf memory a,
            IVyrnBridge.BalanceLeaf memory l,
            IVyrnBridge.SmtProof memory ap,
            IVyrnBridge.SmtProof memory bp
        ) = _leaves();
        vm.expectRevert(IVyrnBridge.BadProof.selector);
        bridge.escapeClaim(a, l, ap, bp);
        bridge.refundDeposit(1);
        assertEq(MockERC20(USDC).balanceOf(user), 11);
    }

    /// The L1 part of 09 §7's guarantee: validators that censor every withdrawal by never posting cannot
    /// hold funds. After CHN_ESCAPE_S anyone, here a stranger, opens escape, and the user exits with a
    /// proof against the last posted root. (09 §7 itself, ForcedPacket, is VYRN-side: README §Scope.)
    function test_forcedExit_whenValidatorsCensorPosts() public {
        _escapeSetup();
        vm.warp(block.timestamp + 14 days);
        vm.prank(address(0x5157));
        bridge.enterEscape();
        (
            IVyrnBridge.AccountLeaf memory a,
            IVyrnBridge.BalanceLeaf memory l,
            IVyrnBridge.SmtProof memory ap,
            IVyrnBridge.SmtProof memory bp
        ) = _leaves();
        vm.prank(address(0x5158)); // a relayer may submit; funds still go to exit_address
        bridge.escapeClaim(a, l, ap, bp);
        assertGt(MockERC20(USDC).balanceOf(a.exitAddress), 0);
    }

    function test_enterEscape_resumesOverManyVetoedPosts() public {
        _escapeSetup();
        IVyrnBridge.Post memory p;
        // 1,100 vetoed posts: more than one ESCAPE_STEP. Written directly is too slow, so propose and veto.
        for (uint64 i = 2; i <= 1_101; ++i) {
            p = _post(i, bytes32(0), 0, 0);
            _propose(p, 0x0f);
            vm.prank(gks[0]);
            bridge.veto(i);
        }
        vm.warp(block.timestamp + 14 days);
        bridge.enterEscape();
        assertFalse(bridge.escapeResolved());
        bridge.enterEscape();
        assertTrue(bridge.escapeResolved());
        assertEq(bridge.escapePostNo(), 1);
    }
}
