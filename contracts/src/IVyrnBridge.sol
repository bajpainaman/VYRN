// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

/// @title VYRN L1 custody and bridge: the external interface (spec/09-chain.md §6, REQ-CHN-6)
/// @notice This file is the contract that relayers, guardians, wallets and the vyrn-chain crate build
/// against. contracts/README.md defines every typed-data struct, leaf encoding and error case, and
/// contracts/vectors/ holds digests for fixed inputs that an off-chain implementation can check.
///
/// Signatures. Bridge keys (BK) sign EIP-712 typed data with the domain
/// {name: "VYRN", version: "1", chainId: <L1 chain id>, verifyingContract: <this contract>}, the same
/// domain as secp256k1 transactions (09 §4.4). Guardian keys (GK) act by sending a transaction.
interface IVyrnBridge {
    // ---------------------------------------------------------------- types (EIP-712 and leaves)

    /// @notice An L1 post (09 §6.2). EIP-712 type:
    /// Post(uint64 postNo,uint32 chainId,bytes32 prevPost,bytes32 commit,bytes32 smtRoot,
    ///      uint64 depositNonce,bytes32 wdRoot,uint32 wdCount,uint256[] wdTotals)
    struct Post {
        uint64 postNo; // 1, 2, 3, ... without gaps
        uint32 chainId; // VYRN chain_id (GenesisRecord.chain_id)
        bytes32 prevPost; // EIP-712 struct hash of the chain's post postNo - 1; not checked on L1
        bytes32 commit; // hash of the StateCommit this post checkpoints (09 §9.5)
        bytes32 smtRoot; // smt_root of that StateCommit (BLAKE3 SMT, 09 §9.3)
        uint64 depositNonce; // highest deposit nonce credited in that state
        bytes32 wdRoot; // keccak256 Merkle root over Withdrawal leaves (README §Withdrawal tree)
        uint32 wdCount; // number of leaves
        uint256[] wdTotals; // per asset, in asset order; length = number of assets
    }

    /// @notice One withdrawal, a leaf of a post's withdrawal tree. Not EIP-712: the leaf is
    /// keccak256(bytes.concat(keccak256(abi.encode(wdId, token, amount, recipient)))), the
    /// OpenZeppelin StandardMerkleTree leaf for types (uint64, address, uint256, address).
    struct Withdrawal {
        uint64 wdId;
        address token;
        uint256 amount;
        address recipient;
    }

    /// @notice A signer rotation (09 §6.7). EIP-712 type:
    /// SignerSet(uint64 rotationNo,address[] bridgeKeys,address[] guardianKeys)
    /// Exactly 5 distinct non-zero addresses in each list, in OpIdx order.
    struct SignerSet {
        uint64 rotationNo; // the active set's number + 1; the genesis set is 0
        address[] bridgeKeys;
        address[] guardianKeys;
    }

    /// @notice The AccountLeaf of the balance SMT (09 §9.3), needed for exit_address.
    struct AccountLeaf {
        uint32 account;
        uint8 ownerKind; // 0 Ed25519, 1 secp256k1 (EVM address), as in TxEnvelope.scheme
        bytes32 owner; // Ed25519 key, or an EVM address right-aligned (high 12 bytes zero)
        uint64 nonce;
        address exitAddress;
    }

    /// @notice The BalanceLeaf of the balance SMT (09 §9.3).
    struct BalanceLeaf {
        uint32 account;
        uint16 asset; // index into assets()
        uint128 free;
        uint128 allocSum;
        uint128 transit;
        uint128 pendingUnposted;
        uint128 pendingPosted;
    }

    /// @notice A proof in the 256-deep BLAKE3 SMT: bit d of bitmap (most significant bit first) is set
    /// iff the sibling at depth d is not empty; siblings lists the non-empty ones by increasing depth.
    struct SmtProof {
        bytes32 bitmap;
        bytes32[] siblings;
    }

    enum PostStatus {
        None,
        Accepted,
        Vetoed
    }

    // ---------------------------------------------------------------- events

    /// @notice 09 §6.2. Validators attest this event from finalized L1 blocks only (09 §6.3).
    event Deposited(
        uint64 nonce, address token, uint256 amount, uint8 ownerKind, bytes32 owner, address sender
    );
    event PostAccepted(
        uint64 indexed postNo, bytes32 postHash, bytes32 commit, bytes32 smtRoot, bool overridden
    );
    event PostVetoed(uint64 indexed postNo, address guardian);
    event Claimed(
        uint64 indexed postNo, uint64 indexed wdId, address token, uint256 amount, address recipient
    );
    event Paused(uint64 pauseNo, address guardian);
    event UnpauseScheduled(uint64 pauseNo, uint64 effectiveAt);
    event RotationQueued(uint64 rotationNo, bytes32 setHash, uint64 activatesAt, bool vetoable);
    event RotationVetoed(uint64 rotationNo, address guardian);
    event SignersRotated(uint64 rotationNo);
    event EscapeEntered(uint64 lastPostNo);
    event EscapeResolved(uint64 postNo, bytes32 smtRoot, uint64 depositNonce);
    event EscapeClaimed(uint32 indexed account, uint16 asset, address to, uint256 amount);
    event DepositRefunded(uint64 indexed nonce, address to, uint256 amount);

    // ---------------------------------------------------------------- errors

    error BadAsset();
    error BadAmount();
    error BadOwner();
    error BadSignature();
    error UnknownSigner();
    error DuplicateSigner();
    error NotEnoughSignatures();
    error NotGuardian();
    error IsPaused();
    error NotPaused();
    error UnpausePending();
    error InEscape();
    error NotInEscape();
    error EscapeUnresolved();
    error EscapeNotDue();
    error BadPost();
    error WrongPostNo();
    error PostNotVetoable();
    error PostNotClaimable();
    error AlreadyClaimed();
    error BadProof();
    error OverPostTotal();
    error OverDailyCap();
    error BadSignerSet();
    error WrongRotationNo();
    error RotationPending();
    error NoVetoableRotation();
    error NotRefundable();
    error TransferFailed();

    // ---------------------------------------------------------------- 09 §6.2 functions

    /// @notice Lock `amount` of a listed `token` for `owner`. Assigns the next nonce (from 1).
    function deposit(address token, uint256 amount, uint8 ownerKind, bytes32 owner) external;

    /// @notice Accept a post signed by >= 4 distinct current bridge keys. A vetoed post number is
    /// accepted again only with 5 signatures, or with 4 once CHN_VETO_OVERRIDE_S has passed.
    function proposePost(Post calldata p, bytes[] calldata bridgeSigs) external;

    /// @notice Any one current guardian vetoes an accepted post inside its challenge period.
    function veto(uint64 postNo) external;

    /// @notice Pay one withdrawal of an accepted post whose challenge period has passed.
    function claim(uint64 postNo, Withdrawal calldata w, bytes32[] calldata proof) external;

    /// @notice Any one current guardian pauses; a pause also cancels a scheduled unpause.
    function pause() external;

    /// @notice 4 bridge keys sign Unpause(uint64 pauseNo); the pause ends CHN_UNPAUSE_DELAY_S later.
    function unpause(bytes[] calldata bridgeSigs) external;

    /// @notice 4 current bridge keys queue a new signer set for CHN_BRIDGE_ROTATE_S; any guardian may
    /// veto it then. 5 signatures queue it unvetoably, which is also the only way after a veto.
    function rotateSigners(SignerSet calldata s, bytes[] calldata bridgeSigs) external;

    /// @notice A guardian vetoes the queued rotation (09 §6.7 step 3; not named in 09 §6.2).
    function vetoRotation(uint64 rotationNo) external;

    /// @notice Anyone, once no post was accepted for CHN_ESCAPE_S. Permanent. Each call also resumes
    /// finding the escape post (the highest accepted, unvetoed post) in steps of at most 1,024.
    function enterEscape() external;

    /// @notice Escape mode: pay free + allocSum + transit + pendingUnposted to the exit address.
    /// Differs from 09 §6.2, which passes only the BalanceLeaf: exit_address is in the AccountLeaf.
    function escapeClaim(
        AccountLeaf calldata a,
        BalanceLeaf calldata l,
        SmtProof calldata accountProof,
        SmtProof calldata balanceProof
    ) external;

    /// @notice Escape mode: return a deposit whose nonce is above the escape post's depositNonce.
    function refundDeposit(uint64 nonce) external;

    // ---------------------------------------------------------------- views

    function domainSeparator() external view returns (bytes32);
    function hashPost(Post calldata p) external view returns (bytes32 digest);
    function hashUnpause(uint64 pauseNo) external view returns (bytes32 digest);
    function hashSignerSet(SignerSet calldata s) external view returns (bytes32 digest);
    function assets() external view returns (address[] memory);
    function isPaused() external view returns (bool);
}
