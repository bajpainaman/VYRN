// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

import {BridgeBase} from "./BridgeBase.sol";
import {VyrnBridge} from "../src/VyrnBridge.sol";
import {IVyrnBridge} from "../src/IVyrnBridge.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// Every path of 09 §6: deposits, posts and claims, veto, pause, rotation. Escape is in Escape.t.sol.
contract VyrnBridgeTest is BridgeBase {
    uint256 constant ALL = 0x1f;
    uint256 constant FOUR = 0x0f;
    uint256 constant THREE = 0x07;

    // ---------------------------------------------------------------- deposits (09 §6.3)

    function test_deposit_assignsNoncesAndEmits() public {
        MockERC20(USDC).mint(user, 5);
        vm.startPrank(user);
        MockERC20(USDC).approve(address(bridge), 5);
        vm.expectEmit(address(bridge));
        emit IVyrnBridge.Deposited(1, USDC, 2, 0, bytes32(uint256(0xed)), user);
        bridge.deposit(USDC, 2, 0, bytes32(uint256(0xed)));
        vm.expectEmit(address(bridge));
        emit IVyrnBridge.Deposited(2, USDC, 3, 1, bytes32(uint256(uint160(user))), user);
        bridge.deposit(USDC, 3, 1, bytes32(uint256(uint160(user))));
        vm.stopPrank();
        assertEq(bridge.depositCount(), 2);
        assertEq(MockERC20(USDC).balanceOf(address(bridge)), 5);
        assertEq(bridge.deposits(2).sender, user);
        assertEq(bridge.deposits(2).amount, 3);
    }

    function test_deposit_rejects() public {
        MockERC20(USDC).mint(user, 10);
        vm.startPrank(user);
        MockERC20(USDC).approve(address(bridge), 10);
        vm.expectRevert(IVyrnBridge.BadAsset.selector);
        bridge.deposit(address(0xdead), 1, 1, bytes32(uint256(1)));
        vm.expectRevert(IVyrnBridge.BadAmount.selector);
        bridge.deposit(USDC, 0, 1, bytes32(uint256(1)));
        vm.expectRevert(IVyrnBridge.BadOwner.selector);
        bridge.deposit(USDC, 1, 2, bytes32(uint256(1)));
        vm.expectRevert(IVyrnBridge.BadOwner.selector);
        bridge.deposit(USDC, 1, 1, bytes32(uint256(1) << 160)); // EVM owner with high bytes set
        vm.expectRevert(IVyrnBridge.BadOwner.selector);
        bridge.deposit(USDC, 1, 0, bytes32(0));
        vm.stopPrank();
        MockERC20(USDC).setFee(100); // fee-on-transfer: 1% of 10 is 0, of 1,000 is 10
        vm.startPrank(user);
        bridge.deposit(USDC, 10, 1, bytes32(uint256(1)));
        MockERC20(USDC).mint(user, 1_000);
        MockERC20(USDC).approve(address(bridge), 1_000);
        vm.expectRevert(IVyrnBridge.BadAmount.selector);
        bridge.deposit(USDC, 1_000, 1, bytes32(uint256(1)));
        vm.stopPrank();
    }

    // ---------------------------------------------------------------- posts and claims (09 §6.4)

    function test_withdrawal_fourOfFive_claimAfterChallenge() public {
        _fund();
        IVyrnBridge.Post memory p = _wdPost(1);
        _propose(p, 0x1e); // keys 1..4
        uint256 t = _acceptedAt(1);
        assertEq(bridge.lastPostNo(), 1);
        vm.warp(t + 3_599);
        (IVyrnBridge.Withdrawal memory w, bytes32[] memory proof) = _wd(0);
        vm.expectRevert(IVyrnBridge.PostNotClaimable.selector);
        bridge.claim(1, w, proof);
        vm.warp(t + 3_600);
        bridge.claim(1, w, proof);
        assertEq(MockERC20(USDC).balanceOf(w.recipient), w.amount);
        vm.expectRevert(IVyrnBridge.AlreadyClaimed.selector);
        bridge.claim(1, w, proof);
        _claim(1, 1);
        _claim(1, 2);
        assertEq(bridge.postClaimed(1, 0), 4_500_000);
    }

    function test_claim_rejectsBadProofAndOverTotal() public {
        _fund();
        // Same tree, but the post's USDC total covers only withdrawal 1.
        IVyrnBridge.Post memory p =
            _post(1, vm.parseJsonBytes32(wdJson, ".root"), 1_000_000, 250_000_000_000_000_000);
        _propose(p, FOUR);
        vm.warp(block.timestamp + 3_600);
        (IVyrnBridge.Withdrawal memory w, bytes32[] memory proof) = _wd(2);
        (IVyrnBridge.Withdrawal memory bad,) = _wd(2);
        bad.amount += 1;
        vm.expectRevert(IVyrnBridge.BadProof.selector);
        bridge.claim(1, bad, proof);
        (bad,) = _wd(2);
        bad.recipient = address(0xbad);
        vm.expectRevert(IVyrnBridge.BadProof.selector);
        bridge.claim(1, bad, proof);
        _claim(1, 0);
        vm.expectRevert(IVyrnBridge.OverPostTotal.selector);
        bridge.claim(1, w, proof);
    }

    function test_propose_rejectsShape() public {
        _fund();
        IVyrnBridge.Post memory p = _wdPost(2);
        _proposeExpect(p, FOUR, IVyrnBridge.WrongPostNo.selector);
        p = _wdPost(1);
        p.chainId = 8;
        _proposeExpect(p, FOUR, IVyrnBridge.BadPost.selector);
        p = _wdPost(1);
        p.depositNonce = 4; // only 3 deposits exist
        _proposeExpect(p, FOUR, IVyrnBridge.BadPost.selector);
        p = _wdPost(1);
        p.wdTotals = new uint256[](3);
        _proposeExpect(p, FOUR, IVyrnBridge.BadPost.selector);
        _propose(_wdPost(1), FOUR);
        _proposeExpect(_wdPost(1), ALL, IVyrnBridge.WrongPostNo.selector); // an accepted number is never replaced
    }

    function test_signatures_fewerThanFourRejected() public {
        IVyrnBridge.Post memory p = _wdPost(1);
        _proposeExpect(p, THREE, IVyrnBridge.NotEnoughSignatures.selector);
        vm.expectRevert(IVyrnBridge.NotEnoughSignatures.selector);
        bridge.proposePost(p, new bytes[](0));
    }

    function test_signatures_duplicateRejected() public {
        IVyrnBridge.Post memory p = _wdPost(1);
        bytes32 d = bridge.hashPost(p);
        bytes[] memory s = _sigs(bkPk, FOUR, d);
        s[3] = s[1];
        vm.expectRevert(IVyrnBridge.DuplicateSigner.selector);
        bridge.proposePost(p, s);
        // Five signatures with one repeated still count as a duplicate, not as five.
        bytes[] memory five = new bytes[](5);
        for (uint256 i = 0; i < 4; ++i) {
            five[i] = s[i];
        }
        five[3] = _sign(bkPk[3], d);
        five[4] = five[0];
        vm.expectRevert(IVyrnBridge.DuplicateSigner.selector);
        bridge.proposePost(p, five);
    }

    function test_signatures_badOrUnknownRejected() public {
        IVyrnBridge.Post memory p = _wdPost(1);
        bytes32 d = bridge.hashPost(p);
        bytes[] memory s = _sigs(bkPk, FOUR, d);
        s[0] = _sign(gkPk[0], d); // a guardian key is not a bridge key
        vm.expectRevert(IVyrnBridge.UnknownSigner.selector);
        bridge.proposePost(p, s);
        s = _sigs(bkPk, FOUR, d);
        s[2] = _sign(bkPk[2], keccak256("other digest"));
        vm.expectRevert(IVyrnBridge.UnknownSigner.selector);
        bridge.proposePost(p, s);
        // The malleable twin (n - s, flipped v) of a valid signature is rejected.
        s = _sigs(bkPk, FOUR, d);
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(bkPk[0], d);
        uint256 n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
        s[0] = abi.encodePacked(r, bytes32(n - uint256(ss)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(IVyrnBridge.BadSignature.selector);
        bridge.proposePost(p, s);
        s[0] = abi.encodePacked(r, ss); // 64 bytes
        vm.expectRevert(IVyrnBridge.BadSignature.selector);
        bridge.proposePost(p, s);
        s[0] = abi.encodePacked(r, ss, uint8(0));
        vm.expectRevert(IVyrnBridge.BadSignature.selector);
        bridge.proposePost(p, s);
    }

    /// Any subset of the 5 keys, in any order, with optional repeats and strangers: accepted iff it has
    /// >= 4 distinct keys, no repeat and no stranger.
    function testFuzz_signatureSets(uint8 mask, uint256 order, bool repeat, bool stranger) public {
        mask &= 0x1f;
        IVyrnBridge.Post memory p = _wdPost(1);
        bytes32 d = bridge.hashPost(p);
        bytes[] memory base = _sigs(bkPk, mask, d);
        uint256 n = base.length;
        uint256 extra = (repeat && n > 0 ? 1 : 0) + (stranger ? 1 : 0);
        bytes[] memory s = new bytes[](n + extra);
        for (uint256 i = 0; i < n; ++i) {
            s[i] = base[i];
        }
        uint256 k = n;
        if (repeat && n > 0) s[k++] = base[order % n];
        if (stranger) s[k++] = _sign(uint256(keccak256(abi.encode(order))) % 2 ** 128 + 1, d);
        for (uint256 i = s.length; i > 1; --i) {
            uint256 j = uint256(keccak256(abi.encode(order, i))) % i;
            (s[i - 1], s[j]) = (s[j], s[i - 1]);
        }
        bool ok = n >= 4 && !(repeat && n > 0) && !stranger;
        if (!ok) vm.expectRevert();
        bridge.proposePost(p, s);
        assertEq(bridge.lastPostNo(), ok ? 1 : 0);
    }

    function test_dailyCap() public {
        _deposit(USDC, 10_000_000); // cap: 1,000,000 per rolling window
        IVyrnBridge.Post memory p = _wdPost(1);
        _propose(p, FOUR);
        vm.warp(block.timestamp + 3_600);
        _claim(1, 0); // 1,000,000: exactly the cap
        uint256 t = block.timestamp;
        (IVyrnBridge.Withdrawal memory w, bytes32[] memory proof) = _wd(2);
        vm.expectRevert(IVyrnBridge.OverDailyCap.selector);
        bridge.claim(1, w, proof);
        vm.warp(t + 24 hours);
        vm.expectRevert(IVyrnBridge.OverDailyCap.selector);
        bridge.claim(1, w, proof);
        _deposit(USDC, 40_000_000); // cap grows with the balance: (49M + 1M used) / 10 = 5M
        bridge.claim(1, w, proof);
        assertEq(MockERC20(USDC).balanceOf(w.recipient), 3_500_000);
    }

    function test_dailyCap_windowRolls() public {
        _deposit(USDC, 10_000_000);
        _propose(_wdPost(1), FOUR);
        vm.warp(block.timestamp + 3_600);
        _claim(1, 0);
        (uint256 used,) = bridge.capState(0);
        assertEq(used, 1_000_000);
        vm.warp(block.timestamp + 25 hours); // 25 hourly buckets: every 24 h interval is covered
        (used,) = bridge.capState(0);
        assertEq(used, 0);
    }

    // ---------------------------------------------------------------- veto (09 §6.5)

    function test_veto_challengeWindowBoundary() public {
        _fund();
        _propose(_wdPost(1), FOUR);
        uint256 t = _acceptedAt(1);
        vm.warp(t + 3_600);
        vm.prank(gks[2]);
        vm.expectRevert(IVyrnBridge.PostNotVetoable.selector);
        bridge.veto(1);
        vm.warp(t + 3_599);
        vm.prank(address(0xbeef));
        vm.expectRevert(IVyrnBridge.NotGuardian.selector);
        bridge.veto(1);
        vm.prank(bks[0]); // a bridge key is not a guardian
        vm.expectRevert(IVyrnBridge.NotGuardian.selector);
        bridge.veto(1);
        vm.prank(gks[2]);
        bridge.veto(1);
        vm.warp(t + 7_200);
        (IVyrnBridge.Withdrawal memory w, bytes32[] memory proof) = _wd(0);
        vm.expectRevert(IVyrnBridge.PostNotClaimable.selector);
        bridge.claim(1, w, proof);
        vm.prank(gks[0]);
        vm.expectRevert(IVyrnBridge.PostNotVetoable.selector);
        bridge.veto(1);
    }

    function test_veto_overrideBoundaries() public {
        _fund();
        _propose(_wdPost(1), FOUR);
        vm.prank(gks[0]);
        bridge.veto(1);
        uint256 tv = block.timestamp;
        // Later posts are not blocked by a vetoed one.
        _propose(_wdPost(2), FOUR);
        assertEq(bridge.lastPostNo(), 2);
        vm.warp(tv + 259_199);
        _proposeExpect(_wdPost(1), FOUR, IVyrnBridge.NotEnoughSignatures.selector);
        vm.warp(tv + 259_200);
        _propose(_wdPost(1), FOUR);
        (VyrnBridge.PostRec memory r,) = bridge.posts(1);
        assertTrue(r.overridden);
        // A post accepted by override cannot be vetoed again.
        vm.prank(gks[1]);
        vm.expectRevert(IVyrnBridge.PostNotVetoable.selector);
        bridge.veto(1);
        vm.warp(block.timestamp + 3_600);
        _claim(1, 0);
        // Its withdrawal also appears in post 2; wdId stops a second payment.
        (IVyrnBridge.Withdrawal memory w, bytes32[] memory proof) = _wd(0);
        vm.expectRevert(IVyrnBridge.AlreadyClaimed.selector);
        bridge.claim(2, w, proof);
    }

    function test_veto_fiveOfFiveOverridesAtOnce() public {
        _fund();
        _propose(_wdPost(1), FOUR);
        vm.prank(gks[4]);
        bridge.veto(1);
        _propose(_wdPost(1), ALL);
        (VyrnBridge.PostRec memory r,) = bridge.posts(1);
        assertEq(uint8(r.status), uint8(IVyrnBridge.PostStatus.Accepted));
        assertTrue(r.overridden);
    }

    // ---------------------------------------------------------------- pause (09 §6.6)

    function test_pause_blocksAndUnpauseAfter24h() public {
        _fund();
        _propose(_wdPost(1), FOUR);
        vm.warp(block.timestamp + 3_600);
        vm.prank(address(0xbeef));
        vm.expectRevert(IVyrnBridge.NotGuardian.selector);
        bridge.pause();
        vm.prank(gks[3]);
        bridge.pause();
        assertTrue(bridge.isPaused());
        vm.expectRevert(IVyrnBridge.IsPaused.selector);
        bridge.deposit(USDC, 1, 1, bytes32(uint256(1)));
        _proposeExpect(_wdPost(2), FOUR, IVyrnBridge.IsPaused.selector);
        (IVyrnBridge.Withdrawal memory w, bytes32[] memory proof) = _wd(0);
        vm.expectRevert(IVyrnBridge.IsPaused.selector);
        bridge.claim(1, w, proof);
        vm.prank(gks[1]);
        vm.expectRevert(IVyrnBridge.IsPaused.selector);
        bridge.pause();
        bytes32 d = bridge.hashUnpause(1);
        {
            bytes[] memory us = _sigs(bkPk, THREE, d);
            vm.expectRevert(IVyrnBridge.NotEnoughSignatures.selector);
            bridge.unpause(us);
        }
        bridge.unpause(_sigs(bkPk, FOUR, d));
        uint256 t = block.timestamp;
        {
            bytes[] memory us = _sigs(bkPk, FOUR, d);
            vm.expectRevert(IVyrnBridge.UnpausePending.selector);
            bridge.unpause(us);
        }
        vm.warp(t + 86_399);
        assertTrue(bridge.isPaused());
        vm.expectRevert(IVyrnBridge.IsPaused.selector);
        bridge.claim(1, w, proof);
        vm.warp(t + 86_400);
        assertFalse(bridge.isPaused());
        bridge.claim(1, w, proof);
        {
            bytes[] memory us = _sigs(bkPk, FOUR, d);
            vm.expectRevert(IVyrnBridge.NotPaused.selector);
            bridge.unpause(us);
        }
    }

    function test_pause_cancelsScheduledUnpause() public {
        vm.prank(gks[0]);
        bridge.pause();
        bytes32 d1 = bridge.hashUnpause(1);
        bridge.unpause(_sigs(bkPk, FOUR, d1));
        vm.warp(block.timestamp + 3_600);
        vm.prank(gks[1]);
        bridge.pause(); // pause 2 cancels the scheduled unpause
        assertEq(bridge.pauseNo(), 2);
        assertEq(bridge.unpauseAt(), 0);
        vm.warp(block.timestamp + 2 days);
        assertTrue(bridge.isPaused());
        // Signatures for pause 1 do not end pause 2.
        {
            bytes[] memory us = _sigs(bkPk, FOUR, d1);
            vm.expectRevert(IVyrnBridge.UnknownSigner.selector);
            bridge.unpause(us);
        }
        bridge.unpause(_sigs(bkPk, FOUR, bridge.hashUnpause(2)));
    }

    // ---------------------------------------------------------------- rotation (09 §6.7)

    function _newSet(uint64 no)
        internal
        pure
        returns (IVyrnBridge.SignerSet memory s, uint256[5] memory pks)
    {
        s.rotationNo = no;
        s.bridgeKeys = new address[](5);
        s.guardianKeys = new address[](5);
        for (uint256 i = 0; i < 5; ++i) {
            pks[i] = 0x3001 + i;
            s.bridgeKeys[i] = vm.addr(pks[i]);
            s.guardianKeys[i] = vm.addr(0x4001 + i);
        }
    }

    function test_rotation_queuedThenActive() public {
        _fund();
        _propose(_wdPost(1), FOUR); // accepted under the old set
        (IVyrnBridge.SignerSet memory s, uint256[5] memory nk) = _newSet(1);
        bytes32 d = bridge.hashSignerSet(s);
        _rotateExpect(s, THREE, IVyrnBridge.NotEnoughSignatures.selector);
        bridge.rotateSigners(s, _sigs(bkPk, FOUR, d));
        uint256 t = block.timestamp;
        _rotateExpect(s, ALL, IVyrnBridge.RotationPending.selector);
        IVyrnBridge.Post memory p2 = _wdPost(2);
        vm.warp(t + 259_199);
        assertEq(bridge.currentRotation(), 0);
        bytes32 pd = bridge.hashPost(p2);
        bytes[] memory newSigs = new bytes[](4);
        for (uint256 i = 0; i < 4; ++i) {
            newSigs[i] = _sign(nk[i], pd);
        }
        vm.expectRevert(IVyrnBridge.UnknownSigner.selector);
        bridge.proposePost(p2, newSigs);
        vm.warp(t + 259_200);
        assertEq(bridge.currentRotation(), 1);
        _proposeExpect(p2, FOUR, IVyrnBridge.UnknownSigner.selector); // old keys no longer sign
        vm.expectEmit(address(bridge));
        emit IVyrnBridge.SignersRotated(1);
        bridge.proposePost(p2, newSigs);
        // Guardian keys rotated with the set.
        vm.prank(gks[0]);
        vm.expectRevert(IVyrnBridge.NotGuardian.selector);
        bridge.pause();
        assertTrue(bridge.isGuardian(s.guardianKeys[0]));
        // Post 1, accepted under the old set, stays claimable.
        _claim(1, 0);
    }

    function test_rotation_vetoAndFiveOfFiveOverride() public {
        (IVyrnBridge.SignerSet memory s,) = _newSet(1);
        bytes32 d = bridge.hashSignerSet(s);
        bridge.rotateSigners(s, _sigs(bkPk, FOUR, d));
        uint256 t = block.timestamp;
        vm.prank(address(0xbeef));
        vm.expectRevert(IVyrnBridge.NotGuardian.selector);
        bridge.vetoRotation(1);
        vm.warp(t + 259_199);
        vm.prank(gks[2]);
        bridge.vetoRotation(1);
        vm.warp(t + 259_200);
        assertEq(bridge.currentRotation(), 0); // vetoed: never activates
        _rotateExpect(s, FOUR, IVyrnBridge.NotEnoughSignatures.selector);
        // A different set may be queued under the same number, also only with 5-of-5.
        s.guardianKeys[4] = address(0x9999);
        d = bridge.hashSignerSet(s);
        bridge.rotateSigners(s, _sigs(bkPk, ALL, d));
        vm.prank(gks[2]);
        vm.expectRevert(IVyrnBridge.NoVetoableRotation.selector);
        bridge.vetoRotation(1);
        vm.warp(block.timestamp + 259_200);
        assertEq(bridge.currentRotation(), 1);
        assertTrue(bridge.isGuardian(address(0x9999)));
        assertFalse(bridge.isGuardian(vm.addr(0x4005)));
    }

    function test_rotation_vetoWindowBoundary() public {
        (IVyrnBridge.SignerSet memory s,) = _newSet(1);
        bridge.rotateSigners(s, _sigs(bkPk, FOUR, bridge.hashSignerSet(s)));
        vm.warp(block.timestamp + 259_200);
        vm.prank(gks[0]); // the old guardian is no longer one, and the rotation is no longer pending
        vm.expectRevert(IVyrnBridge.NotGuardian.selector);
        bridge.vetoRotation(1);
        vm.prank(s.guardianKeys[0]);
        vm.expectRevert(IVyrnBridge.NoVetoableRotation.selector);
        bridge.vetoRotation(1);
    }

    function test_rotation_rejectsBadSets() public {
        (IVyrnBridge.SignerSet memory s,) = _newSet(2);
        _rotateExpect(s, FOUR, IVyrnBridge.WrongRotationNo.selector);
        (s,) = _newSet(1);
        s.bridgeKeys[3] = s.bridgeKeys[1];
        _rotateExpect(s, FOUR, IVyrnBridge.BadSignerSet.selector);
        (s,) = _newSet(1);
        s.guardianKeys[0] = address(0);
        _rotateExpect(s, FOUR, IVyrnBridge.BadSignerSet.selector);
        (s,) = _newSet(1);
        address[] memory four = new address[](4);
        s.bridgeKeys = four;
        _rotateExpect(s, FOUR, IVyrnBridge.BadSignerSet.selector);
    }
}
