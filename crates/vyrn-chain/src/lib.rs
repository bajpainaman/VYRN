//! Chain mode (spec/09-chain.md): the L1-facing bridge codec and the balance SMT, first.
//!
//! # Contract
//!
//! This crate turns finalized VYRN state into the bytes that Ethereum L1 and light clients check,
//! and checks bytes they produce. Every format below is fixed by a spec section and by the
//! conformance vectors in `contracts/vectors/`, which were computed without this crate
//! (eth-account, `cast`, `@openzeppelin/merkle-tree`, Python `blake3`). `tests/vectors.rs` runs
//! them; another implementation passes when it reproduces every value in those files.
//!
//! | Module | Format | Spec | Writer | Readers |
//! |---|---|---|---|---|
//! | [`eip712`] | `Post`, `Unpause`, `SignerSet` digests; 65-byte `r‖s‖v` bridge-key signatures, 4 of 5 | 09 §6.2, §6.5, §6.7; contracts/README §Typed data | the validators' bridge keys (HSM) | `VyrnBridge._countSigs` on L1, guardians, relayers |
//! | [`wdtree`] | keccak256 sorted-pair Merkle tree of `Withdrawal` (OpenZeppelin `StandardMerkleTree`) | 09 §6.2 | the post builder, [`bridge::build_post`] | `VyrnBridge.claim`, wallets |
//! | [`smt`] | BLAKE3 sparse Merkle tree, depth 256; `AccountLeaf`, `BalanceLeaf` | 09 §9.3; contracts/README §Leaf encoding | the commit box | `VyrnBridge.escapeClaim`, light clients (09 §10.4) |
//! | [`smtinc`] | the same tree, updated in place from a batch of dirty leaves | 09 §9.3 net diff, B-CHN-2 | the commit box | [`smt::Proof`] readers |
//! | [`bridge`] | [`bridge::Checkpoint`] → `Post`; the guardian's veto decision | 09 §6.4, §6.5 | validators (build), guardians (review) | relayers, L1 |
//! | [`session`] | `SessionOpen` (item 0x01), checks 2–4 | 09 §5.2 | wallets | every validator |
//! | [`tesla`] | `K_seq`, `K_out`, `K_com` chain and anchor; `KeyDisclosure` (45 B) | 09 §5.3, §5.4, §5.10 | clients, sequencer node, committee members | validators' `tag_com` check, third-party auditors |
//! | [`loghash`] | `log_hash(H)` over each chain block's three roots | 09 §9.2 | validator boxes | voters (check 7), sync, `HandoffRecord` |
//! | [`lthash`] | 28-byte order element, 1024 × u16 LtHash, digest | 09 §9.4 | lanes (diffs), the commit box (sum) | `StateCommit`, syncing nodes |
//! | [`commit`] | `StateCommit` (226 + 10·books B), `CommitVote`, `CommitCert` (item 0x24) | 09 §9.5 | validator boxes (VK) | light clients, L1 posts, `DoubleCommit` evidence |
//! | [`signer`] | `Ed25519Signer` (VK), `BridgeSigner` (BK) traits; software signers | 09 §2.2 | HSM / key-file adapters | [`commit`], bridge posts |
//! | [`keccak256`] | Keccak-256 (Ethereum padding), RustCrypto `sha3` (11 §2.2) | 01 §14.11 | — | [`eip712`], [`wdtree`] |
//!
//! **Ordering.** Post `k` names post `k − 1` by its EIP-712 struct hash in `prev_post`; post 1 has
//! zero. A post's `commit` and `smt_root` are those of a finalized `StateCommit` whose SMT already
//! has the post's withdrawals debited (09 §6.4), so escape never pays twice. `wd_totals` follows
//! the bridge's `assets()` order. SMT proof siblings run in increasing depth. Withdrawal-tree
//! leaves are sorted by hash.
//!
//! **Reject reasons.** [`eip712::count_sigs`] returns the contract's own errors in the contract's
//! order: `BadSignature` (not 65 bytes, `v` ∉ {27, 28}, `s` > n/2, `r`/`s` out of range, no key
//! recovers), `UnknownSigner`, `DuplicateSigner`, `NotEnoughSignatures` (< 4 distinct). One bad
//! signature rejects the set. [`smt::Proof::root`] returns `None` when the sibling count differs
//! from the bitmap's population count. [`bridge::build_post`] rejects an unlisted token, a total
//! that overflows u128, and more than u32::MAX withdrawals. [`bridge::Guardian::review`] vetoes a post that is
//! not the chain's own post with that number, an unknown commit, an unknown predecessor, or any
//! field that differs from its own computation.
//!
//! Nothing here panics on input bytes, allocates on a hot path, or runs on a pinned core: CHAIN
//! mode's L1 and commitment work runs on the commit box and the control thread (09 §9.6).
//!
//! # What this crate reads from other crates
//!
//! `vyrn-chain` sits in layer 7, above `vyrn-replica` and `vyrn-epoch` (spec/11-build.md §1.4). It
//! reads each through a narrow trait it owns. [`Epochs`] is implemented here over
//! [`vyrn_epoch::BridgeSignerTable`], which owns the bridge signer table (09 §6.7: rotated at epoch
//! boundaries). `vyrn-replica` is not a dependency yet, so [`Replica`] has no implementation here;
//! wiring it is a follow-up.
//!
//! # Not implemented yet
//!
//! The wallet signature of the `TxEnvelope` (§4.4) and `AnchorFault` (§5.4), slashing evidence (§8), forced inclusion (§7),
//! L1 deposit attestation (§6.3), and the `AllocLeaf`/`SessionLeaf`/`OperatorLeaf` layouts.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod bridge;
mod codec;
pub mod commit;
pub mod eip712;
pub mod loghash;
pub mod lthash;
pub mod session;
pub mod signer;
pub mod smt;
pub mod smtinc;
pub mod tesla;
pub mod wdtree;

use vyrn_types::Hash;

pub use bridge::{Checkpoint, Guardian, Verdict, VetoReason, build_post};
pub use commit::{CommitCert, CommitVote, StateCommit};
pub use eip712::{Address, Domain, Post, SigError, SignerSet, Unpause};
pub use loghash::{LogChain, Roots};
pub use lthash::{LtHash, OrderElem};
pub use session::{OpenReject, SessionOpen, SessionState};
pub use signer::{BridgeSigner, Ed25519Signer, SignerError};
pub use smt::{AccountLeaf, BalanceLeaf, Proof, Smt};
pub use smtinc::IncSmt;
pub use tesla::{ClientKeys, KcomWindow, KeyDisclosure, Traversal};
pub use wdtree::Withdrawal;

/// Keccak-256 as Ethereum uses it (pad `0x01 … 0x80`, not SHA3's `0x06`). 01 §14.11 allows it only
/// in the L1-facing [`eip712`] and [`wdtree`] code.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    keccak256_parts(&[bytes])
}

/// Keccak-256 of the concatenation of `parts`, without building it.
pub fn keccak256_parts(parts: &[&[u8]]) -> [u8; 32] {
    use sha3::Digest as _;
    let mut h = sha3::Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// What CHAIN mode reads from the replica (`vyrn-replica`, 07; 09 §9.3, §9.5). The replica owns
/// the finalized log and the replayed state; this crate only reads it.
pub trait Replica {
    /// The checkpoint of the finalized `StateCommit` with hash `commit`, if this replica computed
    /// it from its own replay. A commit this replica never computed returns `None`.
    fn checkpoint(&self, commit: &Hash) -> Option<Checkpoint>;

    /// The EIP-712 struct hash of the chain's post `post_no` (the one the validators signed), if
    /// the chain has made it.
    fn post_hash(&self, post_no: u64) -> Option<[u8; 32]>;
}

/// What CHAIN mode reads from the epoch and key tables (`vyrn-epoch`, 08; 09 §2.2, §6.7).
pub trait Epochs {
    /// The bridge signer set with L1 rotation number `rotation_no` (genesis 0), as governance
    /// activated it.
    fn bridge_signers(&self, rotation_no: u64) -> Option<SignerSet>;
}

/// The bridge signer table is `vyrn-epoch`'s (09 §6.7, 08 §9.5); this is the only reader.
impl Epochs for vyrn_epoch::BridgeSignerTable {
    fn bridge_signers(&self, rotation_no: u64) -> Option<SignerSet> {
        self.get(rotation_no).map(|s| SignerSet {
            rotation_no: s.rotation_no,
            bridge_keys: s.bridge_keys,
            guardian_keys: s.guardian_keys,
        })
    }
}
