// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

import {IVyrnBridge} from "./IVyrnBridge.sol";
import {SmtVerifier} from "./SmtVerifier.sol";

interface IERC20Min {
    function balanceOf(address) external view returns (uint256);
}

/// @title VYRN L1 custody and bridge (spec/09-chain.md §6, REQ-CHN-6)
/// @notice Immutable: no proxy, no admin, no upgrade (09 §6.1). The asset list, the VYRN chain id and the
/// genesis signer set are fixed at deployment. contracts/README.md is the normative description.
contract VyrnBridge is IVyrnBridge {
    // ---------------------------------------------------------------- 09 §17.1 constants (fixed per instance)

    uint256 public constant SIGNERS = 5;
    uint256 public constant THRESHOLD = 4;
    uint256 public constant CHN_CHALLENGE_S = 3_600;
    uint256 public constant CHN_VETO_OVERRIDE_S = 259_200;
    uint256 public constant CHN_BRIDGE_ROTATE_S = 259_200;
    uint256 public constant CHN_BRIDGE_DAILY_CAP_BPS = 1_000;
    uint256 public constant CHN_ESCAPE_S = 1_209_600;
    /// @notice 09 §6.6: "effective 24 h after the call". Not named in 09 §17.1.
    uint256 public constant CHN_UNPAUSE_DELAY_S = 86_400;
    /// @notice Outflow buckets for the rolling 24 h cap: 25 hourly buckets cover every 24 h interval.
    uint256 public constant CAP_BUCKET_S = 3_600;
    uint256 public constant CAP_BUCKETS = 25;
    uint256 public constant ESCAPE_STEP = 1_024;

    // ---------------------------------------------------------------- EIP-712 (README §Typed data)

    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant POST_TYPEHASH = keccak256(
        "Post(uint64 postNo,uint32 chainId,bytes32 prevPost,bytes32 commit,bytes32 smtRoot,uint64 depositNonce,bytes32 wdRoot,uint32 wdCount,uint256[] wdTotals)"
    );
    bytes32 public constant UNPAUSE_TYPEHASH = keccak256("Unpause(uint64 pauseNo)");
    bytes32 public constant SIGNERSET_TYPEHASH =
        keccak256("SignerSet(uint64 rotationNo,address[] bridgeKeys,address[] guardianKeys)");
    bytes32 private constant NAME_HASH = keccak256("VYRN");
    bytes32 private constant VERSION_HASH = keccak256("1");
    uint256 private constant HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    uint32 public immutable CHAIN_ID;
    /// @notice The escape proof verifier, deployed by the constructor (README §Decisions, code size).
    SmtVerifier public immutable SMT;
    uint256 private immutable DEPLOY_CHAIN;
    bytes32 private immutable DOMAIN;

    // ---------------------------------------------------------------- state

    struct PostRec {
        bytes32 postHash;
        bytes32 smtRoot;
        bytes32 wdRoot;
        uint64 acceptedAt;
        uint64 vetoedAt;
        uint64 depositNonce;
        PostStatus status;
        bool overridden;
    }

    struct DepositRec {
        address sender;
        uint96 assetIdx; // 1-based
        uint256 amount;
    }

    struct PendingRotation {
        uint64 rotationNo;
        uint64 activatesAt;
        bool vetoable;
        bool vetoed;
    }

    address[] private _assets;
    mapping(address => uint256) private _assetIdx; // 1-based; 0 = not listed

    // Signer sets by rotation number: index + 1 of each key, 0 if not in the set.
    mapping(uint64 => mapping(address => uint256)) private _bkIdx;
    mapping(uint64 => mapping(address => uint256)) private _gkIdx;
    uint64 public activeRotation;
    PendingRotation public pendingRotation;

    uint64 public depositCount;
    mapping(uint64 => DepositRec) private _deposits;
    mapping(uint64 => bool) public refunded;

    uint64 public lastPostNo;
    uint64 public lastAcceptedAt;
    mapping(uint64 => PostRec) private _posts;
    mapping(uint64 => uint256[]) private _postTotals;
    mapping(uint64 => mapping(uint256 => uint256)) public postClaimed; // postNo => asset => paid
    mapping(uint64 => uint256) public wdPaid; // wdId => amount paid so far (claims may be partial)

    // asset => hour => outflow by claim
    mapping(uint256 => mapping(uint256 => uint256)) private _outflow;

    bool public paused;
    uint64 public pauseNo;
    uint64 public unpauseAt; // 0 = none scheduled

    bool public escape;
    bool public escapeResolved;
    uint64 public escapeCursor;
    uint64 public escapePostNo; // 0 = no accepted post: every deposit is refundable
    bytes32 public escapeRoot;
    uint64 public escapeDepositNonce;
    mapping(uint32 => mapping(uint256 => bool)) public escapeClaimed;

    // ---------------------------------------------------------------- construction

    constructor(
        uint32 chainId,
        address[] memory assetList,
        address[] memory bridgeKeys,
        address[] memory guardianKeys
    ) {
        if (assetList.length == 0 || assetList.length > type(uint16).max) {
            revert BadAsset();
        }
        for (uint256 i = 0; i < assetList.length; ++i) {
            address t = assetList[i];
            if (t == address(0) || t.code.length == 0 || _assetIdx[t] != 0) revert BadAsset();
            _assetIdx[t] = i + 1;
            _assets.push(t);
        }
        _writeSet(0, bridgeKeys, guardianKeys);
        CHAIN_ID = chainId;
        SMT = new SmtVerifier();
        DEPLOY_CHAIN = block.chainid;
        DOMAIN = _buildDomain();
        lastAcceptedAt = uint64(block.timestamp);
    }

    // ---------------------------------------------------------------- reentrancy guard (EIP-1153)

    modifier nonReentrant() {
        assembly ("memory-safe") {
            if tload(0) {
                mstore(0, 0x3ee5aeb5) // ReentrancyGuardReentrantCall()
                revert(0x1c, 4)
            }
            tstore(0, 1)
        }
        _;
        assembly ("memory-safe") {
            tstore(0, 0)
        }
    }

    // ---------------------------------------------------------------- deposits (09 §6.3)

    function deposit(address token, uint256 amount, uint8 ownerKind, bytes32 owner) external nonReentrant {
        if (escape) revert InEscape();
        if (isPaused()) revert IsPaused();
        uint256 idx = _assetIdx[token];
        if (idx == 0) revert BadAsset();
        if (amount == 0) revert BadAmount();
        if (owner == bytes32(0) || ownerKind > 1 || (ownerKind == 1 && uint256(owner) >> 160 != 0)) {
            revert BadOwner();
        }
        uint256 before = IERC20Min(token).balanceOf(address(this));
        _call(token, abi.encodeWithSelector(0x23b872dd, msg.sender, address(this), amount)); // transferFrom
        // Fee-on-transfer and rebasing tokens are not supported: the credited amount must be exact.
        if (IERC20Min(token).balanceOf(address(this)) - before != amount) revert BadAmount();
        uint64 nonce = ++depositCount;
        _deposits[nonce] = DepositRec(msg.sender, uint96(idx), amount);
        emit Deposited(nonce, token, amount, ownerKind, owner, msg.sender);
    }

    // ---------------------------------------------------------------- posts (09 §6.4, §6.5)

    function proposePost(Post calldata p, bytes[] calldata bridgeSigs) external {
        if (escape) revert InEscape();
        if (isPaused()) revert IsPaused();
        _applyRotation();
        if (p.chainId != CHAIN_ID || p.wdTotals.length != _assets.length || p.depositNonce > depositCount) {
            revert BadPost();
        }
        bytes32 digest = hashPost(p);
        uint256 n = _countSigs(digest, bridgeSigs);
        PostRec storage r = _posts[p.postNo];
        bool overridden;
        if (p.postNo == lastPostNo + 1) {
            lastPostNo = p.postNo;
        } else if (p.postNo != 0 && r.status == PostStatus.Vetoed) {
            // 09 §6.5: only the same post is proposed again; a veto never lets its contents change.
            if (digest != r.postHash) revert BadPost();
            // 09 §6.5: 5-of-5 at once, or 4-of-5 once CHN_VETO_OVERRIDE_S has passed since the veto.
            if (n < SIGNERS && block.timestamp < uint256(r.vetoedAt) + CHN_VETO_OVERRIDE_S) {
                revert NotEnoughSignatures();
            }
            overridden = true;
        } else {
            revert WrongPostNo();
        }
        r.postHash = digest;
        r.smtRoot = p.smtRoot;
        r.wdRoot = p.wdRoot;
        r.acceptedAt = uint64(block.timestamp);
        r.vetoedAt = 0;
        r.depositNonce = p.depositNonce;
        r.status = PostStatus.Accepted;
        r.overridden = overridden;
        _postTotals[p.postNo] = p.wdTotals;
        lastAcceptedAt = uint64(block.timestamp);
        emit PostAccepted(p.postNo, digest, p.commit, p.smtRoot, overridden);
    }

    function veto(uint64 postNo) external {
        if (escape) revert InEscape();
        _applyRotation();
        if (_gkIdx[activeRotation][msg.sender] == 0) revert NotGuardian();
        PostRec storage r = _posts[postNo];
        if (
            r.status != PostStatus.Accepted || r.overridden
                || block.timestamp >= uint256(r.acceptedAt) + CHN_CHALLENGE_S
        ) {
            revert PostNotVetoable();
        }
        r.status = PostStatus.Vetoed;
        r.vetoedAt = uint64(block.timestamp);
        emit PostVetoed(postNo, msg.sender);
    }

    function claim(uint64 postNo, Withdrawal calldata w, bytes32[] calldata proof) external nonReentrant {
        // In escape mode pause no longer applies, so one guardian cannot block exits (README §Decisions).
        if (!escape && isPaused()) revert IsPaused();
        PostRec storage r = _posts[postNo];
        if (r.status != PostStatus.Accepted || block.timestamp < uint256(r.acceptedAt) + CHN_CHALLENGE_S) {
            revert PostNotClaimable();
        }
        uint256 done = wdPaid[w.wdId];
        uint256 idx = _assetIdx[w.token];
        if (idx == 0) revert BadAsset();
        if (w.amount == 0 || w.recipient == address(0)) revert BadAmount();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(w.wdId, w.token, w.amount, w.recipient))));
        if (_merkleRoot(leaf, proof) != r.wdRoot) revert BadProof();
        if (done >= w.amount) revert AlreadyClaimed();
        // Pay what the rolling cap allows now; the rest stays claimable in later windows (09 §6.4).
        (uint256 used, uint256 cap) = capState(idx - 1);
        if (used >= cap) revert OverDailyCap();
        uint256 pay = w.amount - done;
        if (pay > cap - used) pay = cap - used;
        uint256 paid = postClaimed[postNo][idx - 1] + pay;
        if (paid > _postTotals[postNo][idx - 1]) revert OverPostTotal();
        _outflow[idx - 1][block.timestamp / CAP_BUCKET_S] += pay;
        wdPaid[w.wdId] = done + pay;
        postClaimed[postNo][idx - 1] = paid;
        _transfer(w.token, w.recipient, pay);
        emit Claimed(postNo, w.wdId, w.token, pay, w.recipient);
    }

    // ---------------------------------------------------------------- pause (09 §6.6)

    function pause() external {
        if (escape) revert InEscape();
        _applyRotation();
        if (_gkIdx[activeRotation][msg.sender] == 0) revert NotGuardian();
        if (isPaused() && unpauseAt == 0) revert IsPaused();
        paused = true;
        unpauseAt = 0;
        uint64 no = ++pauseNo;
        emit Paused(no, msg.sender);
    }

    function unpause(bytes[] calldata bridgeSigs) external {
        if (escape) revert InEscape();
        _applyRotation();
        if (!isPaused()) revert NotPaused();
        if (unpauseAt != 0) revert UnpausePending();
        _countSigs(hashUnpause(pauseNo), bridgeSigs); // reverts below THRESHOLD
        uint64 at = uint64(block.timestamp + CHN_UNPAUSE_DELAY_S);
        unpauseAt = at;
        emit UnpauseScheduled(pauseNo, at);
    }

    /// @notice Paused from pause() until unpauseAt, when one is scheduled.
    function isPaused() public view returns (bool) {
        return paused && (unpauseAt == 0 || block.timestamp < unpauseAt);
    }

    // ---------------------------------------------------------------- signer rotation (09 §6.7)

    function rotateSigners(SignerSet calldata s, bytes[] calldata bridgeSigs) external {
        if (escape) revert InEscape();
        _applyRotation();
        if (s.rotationNo != activeRotation + 1) revert WrongRotationNo();
        PendingRotation memory pr = pendingRotation;
        bool sameVetoed = pr.rotationNo == s.rotationNo && pr.vetoed;
        if (pr.rotationNo == s.rotationNo && !pr.vetoed) revert RotationPending();
        uint256 n = _countSigs(hashSignerSet(s), bridgeSigs);
        // A vetoed rotation number is queued again only with 5-of-5, which also makes it unvetoable.
        if (sameVetoed && n < SIGNERS) revert NotEnoughSignatures();
        if (sameVetoed) _clearSet(s.rotationNo);
        _writeSet(s.rotationNo, s.bridgeKeys, s.guardianKeys);
        uint64 at = uint64(block.timestamp + CHN_BRIDGE_ROTATE_S);
        bool vetoable = n < SIGNERS;
        pendingRotation = PendingRotation(s.rotationNo, at, vetoable, false);
        emit RotationQueued(s.rotationNo, hashSignerSet(s), at, vetoable);
    }

    function vetoRotation(uint64 rotationNo) external {
        if (escape) revert InEscape();
        _applyRotation();
        if (_gkIdx[activeRotation][msg.sender] == 0) revert NotGuardian();
        PendingRotation storage pr = pendingRotation;
        if (pr.rotationNo != rotationNo || rotationNo != activeRotation + 1 || pr.vetoed || !pr.vetoable) {
            revert NoVetoableRotation();
        }
        pr.vetoed = true;
        emit RotationVetoed(rotationNo, msg.sender);
    }

    /// @notice The set that signs and guards now, including a queued rotation that is due.
    function currentRotation() public view returns (uint64) {
        PendingRotation memory pr = pendingRotation;
        if (pr.rotationNo == activeRotation + 1 && !pr.vetoed && block.timestamp >= pr.activatesAt) {
            return pr.rotationNo;
        }
        return activeRotation;
    }

    function isBridgeKey(address a) external view returns (bool) {
        return _bkIdx[currentRotation()][a] != 0;
    }

    function isGuardian(address a) external view returns (bool) {
        return _gkIdx[currentRotation()][a] != 0;
    }

    // ---------------------------------------------------------------- escape (09 §6.6)

    function enterEscape() external {
        if (!escape) {
            if (block.timestamp < uint256(lastAcceptedAt) + CHN_ESCAPE_S) revert EscapeNotDue();
            escape = true;
            escapeCursor = lastPostNo;
            emit EscapeEntered(lastPostNo);
        } else if (escapeResolved) {
            revert InEscape();
        }
        // The escape post is the highest accepted post that is not vetoed. Vetoed posts above it are
        // skipped in steps of ESCAPE_STEP, so no number of vetoed posts can make this run out of gas.
        uint64 c = escapeCursor;
        for (uint256 i = 0; i < ESCAPE_STEP && c != 0; ++i) {
            if (_posts[c].status == PostStatus.Accepted) break;
            --c;
        }
        escapeCursor = c;
        if (c != 0 && _posts[c].status != PostStatus.Accepted) return; // more to skip; call again
        escapeResolved = true;
        escapePostNo = c;
        escapeRoot = _posts[c].smtRoot;
        escapeDepositNonce = _posts[c].depositNonce;
        emit EscapeResolved(c, escapeRoot, escapeDepositNonce);
    }

    function escapeClaim(
        AccountLeaf calldata a,
        BalanceLeaf calldata l,
        SmtProof calldata accountProof,
        SmtProof calldata balanceProof
    ) external nonReentrant {
        if (!escape) revert NotInEscape();
        if (!escapeResolved) revert EscapeUnresolved();
        if (escapePostNo == 0 || a.account != l.account || l.asset >= _assets.length) revert BadProof();
        if (escapeClaimed[l.account][l.asset]) revert AlreadyClaimed();
        if (a.exitAddress == address(0)) revert BadOwner();
        bytes memory aValue = abi.encodePacked(a.ownerKind, a.owner, _le64(a.nonce), a.exitAddress);
        bytes32 root = escapeRoot;
        if (
            SMT.rootOf(
                    abi.encodePacked(uint8(0x01), _le32(a.account)),
                    aValue,
                    accountProof.bitmap,
                    accountProof.siblings
                ) != root
        ) {
            revert BadProof();
        }
        bytes memory bValue = abi.encodePacked(
            _le128(l.free),
            _le128(l.allocSum),
            _le128(l.transit),
            _le128(l.pendingUnposted),
            _le128(l.pendingPosted)
        );
        if (
            SMT.rootOf(
                    abi.encodePacked(uint8(0x02), _le32(l.account), _le16(l.asset)),
                    bValue,
                    balanceProof.bitmap,
                    balanceProof.siblings
                ) != root
        ) revert BadProof();
        escapeClaimed[l.account][l.asset] = true;
        uint256 amount = uint256(l.free) + l.allocSum + l.transit + l.pendingUnposted;
        address token = _assets[l.asset];
        if (amount != 0) _transfer(token, a.exitAddress, amount);
        emit EscapeClaimed(l.account, l.asset, a.exitAddress, amount);
    }

    function refundDeposit(uint64 nonce) external nonReentrant {
        if (!escape) revert NotInEscape();
        if (!escapeResolved) revert EscapeUnresolved();
        if (nonce <= escapeDepositNonce || nonce > depositCount || refunded[nonce]) revert NotRefundable();
        refunded[nonce] = true;
        DepositRec memory d = _deposits[nonce];
        _transfer(_assets[d.assetIdx - 1], d.sender, d.amount);
        emit DepositRefunded(nonce, d.sender, d.amount);
    }

    // ---------------------------------------------------------------- views

    function domainSeparator() public view returns (bytes32) {
        return block.chainid == DEPLOY_CHAIN ? DOMAIN : _buildDomain();
    }

    function hashPost(Post calldata p) public view returns (bytes32) {
        bytes32 s = keccak256(
            abi.encode(
                POST_TYPEHASH,
                p.postNo,
                p.chainId,
                p.prevPost,
                p.commit,
                p.smtRoot,
                p.depositNonce,
                p.wdRoot,
                p.wdCount,
                keccak256(abi.encodePacked(p.wdTotals))
            )
        );
        return _typed(s);
    }

    function hashUnpause(uint64 no) public view returns (bytes32) {
        return _typed(keccak256(abi.encode(UNPAUSE_TYPEHASH, no)));
    }

    function hashSignerSet(SignerSet calldata s) public view returns (bytes32) {
        return _typed(
            keccak256(
                abi.encode(
                    SIGNERSET_TYPEHASH,
                    s.rotationNo,
                    keccak256(abi.encodePacked(s.bridgeKeys)),
                    keccak256(abi.encodePacked(s.guardianKeys))
                )
            )
        );
    }

    function assets() external view returns (address[] memory) {
        return _assets;
    }

    function posts(uint64 postNo) external view returns (PostRec memory r, uint256[] memory totals) {
        return (_posts[postNo], _postTotals[postNo]);
    }

    function deposits(uint64 nonce) external view returns (DepositRec memory) {
        return _deposits[nonce];
    }

    /// @notice Outflow by claim of asset `idx` in the CAP_BUCKETS hourly buckets up to now, and the cap.
    function capState(uint256 idx) public view returns (uint256 used, uint256 cap) {
        uint256 h = block.timestamp / CAP_BUCKET_S;
        for (uint256 i = 0; i < CAP_BUCKETS && i <= h; ++i) {
            used += _outflow[idx][h - i];
        }
        // The cap is 10% of the balance at the start of the window: the balance now plus what left in it.
        cap = (IERC20Min(_assets[idx]).balanceOf(address(this)) + used) * CHN_BRIDGE_DAILY_CAP_BPS / 10_000;
    }

    // ---------------------------------------------------------------- internals

    function _buildDomain() private view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _typed(bytes32 structHash) private view returns (bytes32 d) {
        bytes32 dom = domainSeparator();
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, hex"1901")
            mstore(add(m, 2), dom)
            mstore(add(m, 34), structHash)
            d := keccak256(m, 66)
        }
    }

    /// @dev Checks every signature: 65 bytes (r, s, v), low s, v 27 or 28, a distinct key of the current
    /// bridge set. Reverts on any bad, unknown or repeated signer, and returns the count (>= THRESHOLD).
    function _countSigs(bytes32 digest, bytes[] calldata sigs) private view returns (uint256 n) {
        uint64 rot = activeRotation;
        uint256 seen;
        for (uint256 i = 0; i < sigs.length; ++i) {
            bytes calldata sig = sigs[i];
            if (sig.length != 65) revert BadSignature();
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly ("memory-safe") {
                r := calldataload(sig.offset)
                s := calldataload(add(sig.offset, 32))
                v := byte(0, calldataload(add(sig.offset, 64)))
            }
            if (uint256(s) > HALF_N || (v != 27 && v != 28)) revert BadSignature();
            address signer = ecrecover(digest, v, r, s);
            if (signer == address(0)) revert BadSignature();
            uint256 idx = _bkIdx[rot][signer];
            if (idx == 0) revert UnknownSigner();
            uint256 bit = 1 << idx;
            if (seen & bit != 0) revert DuplicateSigner();
            seen |= bit;
            ++n;
        }
        if (n < THRESHOLD) revert NotEnoughSignatures();
    }

    function _applyRotation() private {
        uint64 c = currentRotation();
        if (c != activeRotation) {
            activeRotation = c;
            emit SignersRotated(c);
        }
    }

    function _writeSet(uint64 rot, address[] memory bks, address[] memory gks) private {
        if (bks.length != SIGNERS || gks.length != SIGNERS) revert BadSignerSet();
        for (uint256 i = 0; i < SIGNERS; ++i) {
            if (bks[i] == address(0) || _bkIdx[rot][bks[i]] != 0) revert BadSignerSet();
            if (gks[i] == address(0) || _gkIdx[rot][gks[i]] != 0) revert BadSignerSet();
            _bkIdx[rot][bks[i]] = i + 1;
            _gkIdx[rot][gks[i]] = i + 1;
        }
        _setKeys[rot] = abi.encode(bks, gks);
    }

    mapping(uint64 => bytes) private _setKeys;

    function _clearSet(uint64 rot) private {
        (address[] memory bks, address[] memory gks) = abi.decode(_setKeys[rot], (address[], address[]));
        for (uint256 i = 0; i < SIGNERS; ++i) {
            delete _bkIdx[rot][bks[i]];
            delete _gkIdx[rot][gks[i]];
        }
    }

    /// @notice The signer set of rotation `rot`, in OpIdx order.
    function signerSet(uint64 rot) external view returns (address[] memory bks, address[] memory gks) {
        bytes memory b = _setKeys[rot];
        if (b.length != 0) (bks, gks) = abi.decode(b, (address[], address[]));
    }

    /// @dev OpenZeppelin MerkleProof.processProof: sorted-pair keccak256.
    function _merkleRoot(bytes32 leaf, bytes32[] calldata proof) private pure returns (bytes32 h) {
        h = leaf;
        for (uint256 i = 0; i < proof.length; ++i) {
            bytes32 p = proof[i];
            assembly ("memory-safe") {
                switch lt(h, p)
                case 1 {
                    mstore(0, h)
                    mstore(32, p)
                }
                default {
                    mstore(0, p)
                    mstore(32, h)
                }
                h := keccak256(0, 64)
            }
        }
    }

    function _transfer(address token, address to, uint256 amount) private {
        _call(token, abi.encodeWithSelector(0xa9059cbb, to, amount)); // transfer
    }

    /// @dev SafeERC20-style call: the token must have code, and a returned value must be true.
    function _call(address token, bytes memory data) private {
        (bool ok, bytes memory ret) = token.call(data);
        if (!ok || (ret.length != 0 && (ret.length < 32 || !abi.decode(ret, (bool))))) {
            revert TransferFailed();
        }
    }

    function _le16(uint16 x) private pure returns (bytes2) {
        return bytes2(uint16((x >> 8) | (x << 8)));
    }

    function _le32(uint32 x) private pure returns (bytes4) {
        x = ((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8);
        return bytes4((x >> 16) | (x << 16));
    }

    function _le64(uint64 x) private pure returns (bytes8) {
        x = ((x & 0xff00ff00ff00ff00) >> 8) | ((x & 0x00ff00ff00ff00ff) << 8);
        x = ((x & 0xffff0000ffff0000) >> 16) | ((x & 0x0000ffff0000ffff) << 16);
        return bytes8((x >> 32) | (x << 32));
    }

    function _le128(uint128 x) private pure returns (bytes16) {
        x = ((x & 0xff00ff00ff00ff00ff00ff00ff00ff00) >> 8) | ((x & 0x00ff00ff00ff00ff00ff00ff00ff00ff) << 8);
        x = ((x & 0xffff0000ffff0000ffff0000ffff0000) >> 16)
            | ((x & 0x0000ffff0000ffff0000ffff0000ffff) << 16);
        x = ((x & 0xffffffff00000000ffffffff00000000) >> 32)
            | ((x & 0x00000000ffffffff00000000ffffffff) << 32);
        return bytes16((x >> 64) | (x << 64));
    }
}
