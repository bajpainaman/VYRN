//! The bridge's EIP-712 typed data and its 4-of-5 bridge-key signatures (09 §6.2, §6.5, §6.7;
//! `contracts/README.md` §Typed data).
//!
//! Domain `{name: "VYRN", version: "1", chainId, verifyingContract}`. Three primary types:
//!
//! ```text
//! Post(uint64 postNo,uint32 chainId,bytes32 prevPost,bytes32 commit,bytes32 smtRoot,uint64 depositNonce,bytes32 wdRoot,uint32 wdCount,uint256[] wdTotals)
//! Unpause(uint64 pauseNo)
//! SignerSet(uint64 rotationNo,address[] bridgeKeys,address[] guardianKeys)
//! ```
//!
//! `digest = keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)`. A signature is 65 bytes,
//! `r ‖ s ‖ v`, `v` ∈ {27, 28}, `s` ≤ n/2 (EIP-2). [`count_sigs`] applies the contract's
//! `_countSigs` rules in the same order, so a set this crate accepts is a set L1 accepts.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

use crate::{keccak256, keccak256_parts};

/// A 20-byte EVM address.
pub type Address = [u8; 20];

/// Bridge keys and guardian keys per signer set (09 §2.2).
pub const SIGNERS: usize = 5;
/// Distinct bridge-key signatures a post, an unpause or a rotation needs (09 §6.1).
pub const THRESHOLD: usize = 4;

/// `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`.
pub const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
/// The `Post` type string.
pub const POST_TYPE: &str = "Post(uint64 postNo,uint32 chainId,bytes32 prevPost,bytes32 commit,bytes32 smtRoot,uint64 depositNonce,bytes32 wdRoot,uint32 wdCount,uint256[] wdTotals)";
/// The `Unpause` type string.
pub const UNPAUSE_TYPE: &str = "Unpause(uint64 pauseNo)";
/// The `SignerSet` type string.
pub const SIGNER_SET_TYPE: &str =
    "SignerSet(uint64 rotationNo,address[] bridgeKeys,address[] guardianKeys)";

/// secp256k1 n/2, big-endian: the largest `s` EIP-2 allows.
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// A `uint256` as its ABI word: 32 bytes, big-endian.
pub type U256 = [u8; 32];

/// The ABI word of `x`.
pub fn word(x: u128) -> U256 {
    let mut w = [0u8; 32];
    if let Some(tail) = w.get_mut(16..) {
        tail.copy_from_slice(&x.to_be_bytes());
    }
    w
}

fn addr_word(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    if let Some(tail) = w.get_mut(12..) {
        tail.copy_from_slice(a);
    }
    w
}

/// The EIP-712 domain. `name` and `version` are fixed; `chain_id` is the L1 chain id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domain {
    /// L1 chain id (1 for Ethereum mainnet).
    pub chain_id: u64,
    /// The bridge contract.
    pub verifying_contract: Address,
}

impl Domain {
    /// `domainSeparator`.
    pub fn separator(&self) -> [u8; 32] {
        keccak256_parts(&[
            &keccak256(DOMAIN_TYPE.as_bytes()),
            &keccak256(b"VYRN"),
            &keccak256(b"1"),
            &word(u128::from(self.chain_id)),
            &addr_word(&self.verifying_contract),
        ])
    }

    /// The digest a bridge key signs for a struct hash.
    pub fn digest(&self, struct_hash: &[u8; 32]) -> [u8; 32] {
        keccak256_parts(&[&[0x19, 0x01], &self.separator(), struct_hash])
    }
}

/// `Post` (09 §6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Post {
    /// Sequence number on L1; the first post is 1.
    pub post_no: u64,
    /// VYRN chain id (01 §3).
    pub chain_id: u32,
    /// [`Post::struct_hash`] of post `post_no − 1`; zero for post 1.
    pub prev_post: [u8; 32],
    /// Hash of the `StateCommit` this post checkpoints (09 §9.5).
    pub commit: [u8; 32],
    /// The balance-SMT root of that `StateCommit` (09 §9.3).
    pub smt_root: [u8; 32],
    /// Highest deposit nonce credited in that state.
    pub deposit_nonce: u64,
    /// [`crate::wdtree::root`] of the post's withdrawals.
    pub wd_root: [u8; 32],
    /// Number of withdrawals in the tree.
    pub wd_count: u32,
    /// Per-asset totals of the withdrawals, in asset order, at the ABI's uint256 width: one
    /// account's balance is u128 (09 §9.3), but a total over many accounts can exceed it.
    pub wd_totals: Vec<U256>,
}

impl Post {
    /// The EIP-712 struct hash. It is also the next post's `prev_post`.
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut totals = Vec::with_capacity(self.wd_totals.len().saturating_mul(32));
        for t in &self.wd_totals {
            totals.extend_from_slice(t);
        }
        keccak256_parts(&[
            &keccak256(POST_TYPE.as_bytes()),
            &word(u128::from(self.post_no)),
            &word(u128::from(self.chain_id)),
            &self.prev_post,
            &self.commit,
            &self.smt_root,
            &word(u128::from(self.deposit_nonce)),
            &self.wd_root,
            &word(u128::from(self.wd_count)),
            &keccak256(&totals),
        ])
    }
}

/// `Unpause` (contracts/README.md decision 2): names the pause it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unpause {
    /// The pause this ends.
    pub pause_no: u64,
}

impl Unpause {
    /// The EIP-712 struct hash.
    pub fn struct_hash(&self) -> [u8; 32] {
        keccak256_parts(&[
            &keccak256(UNPAUSE_TYPE.as_bytes()),
            &word(u128::from(self.pause_no)),
        ])
    }
}

/// `SignerSet` (09 §6.7): five bridge keys and five guardian keys in `OpIdx` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignerSet {
    /// Rotation number; genesis is 0.
    pub rotation_no: u64,
    /// Bridge keys BK_0..BK_4.
    pub bridge_keys: [Address; SIGNERS],
    /// Guardian keys GK_0..GK_4.
    pub guardian_keys: [Address; SIGNERS],
}

impl SignerSet {
    /// The EIP-712 struct hash.
    pub fn struct_hash(&self) -> [u8; 32] {
        let enc = |keys: &[Address; SIGNERS]| {
            let mut v = Vec::with_capacity(SIGNERS * 32);
            for k in keys {
                v.extend_from_slice(&addr_word(k));
            }
            keccak256(&v)
        };
        keccak256_parts(&[
            &keccak256(SIGNER_SET_TYPE.as_bytes()),
            &word(u128::from(self.rotation_no)),
            &enc(&self.bridge_keys),
            &enc(&self.guardian_keys),
        ])
    }

    /// The contract's `_writeSet` check: no zero key and no repeated key within either list.
    pub fn is_well_formed(&self) -> bool {
        let ok = |keys: &[Address; SIGNERS]| {
            keys.iter()
                .enumerate()
                .all(|(i, k)| *k != [0u8; 20] && !keys.iter().take(i).any(|prev| prev == k))
        };
        ok(&self.bridge_keys) && ok(&self.guardian_keys)
    }
}

/// Why a signature set is rejected. The names and the order of the checks are the contract's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    /// Not 65 bytes, `v` ∉ {27, 28}, high `s`, `r` or `s` out of range, or no key recovers.
    #[error("BadSignature")]
    BadSignature,
    /// The recovered key is not a bridge key of the set.
    #[error("UnknownSigner")]
    UnknownSigner,
    /// Two signatures recover the same bridge key.
    #[error("DuplicateSigner")]
    DuplicateSigner,
    /// Fewer than [`THRESHOLD`] signatures.
    #[error("NotEnoughSignatures")]
    NotEnoughSignatures,
}

/// The EVM address of a secp256k1 public key.
pub fn address_of(key: &VerifyingKey) -> Address {
    let point = key.to_sec1_point(false);
    let bytes = point.as_bytes();
    let h = keccak256(bytes.get(1..).unwrap_or_default());
    let mut a = [0u8; 20];
    if let Some(tail) = h.get(12..) {
        a.copy_from_slice(tail);
    }
    a
}

/// `ecrecover` with the contract's pre-checks: the signer of `digest`, or [`SigError::BadSignature`].
pub fn recover(digest: &[u8; 32], sig: &[u8]) -> Result<Address, SigError> {
    let (rs, v) = match sig {
        [rs @ .., v] if rs.len() == 64 => (rs, *v),
        _ => return Err(SigError::BadSignature),
    };
    let s = rs.get(32..).ok_or(SigError::BadSignature)?;
    if s > HALF_N.as_slice() || !(v == 27 || v == 28) {
        return Err(SigError::BadSignature);
    }
    let sig = Signature::from_slice(rs).map_err(|_| SigError::BadSignature)?;
    let id = RecoveryId::from_byte(v.wrapping_sub(27)).ok_or(SigError::BadSignature)?;
    let key =
        VerifyingKey::recover_from_prehash(digest, &sig, id).map_err(|_| SigError::BadSignature)?;
    Ok(address_of(&key))
}

/// Checks a bridge-key signature set against `bridge_keys`, as L1 does: every signature must be
/// well formed and by a distinct key of the set, and there must be at least [`THRESHOLD`]. The
/// first bad signature rejects the whole set; none is skipped. Returns the bitmask of signers by
/// `OpIdx` (bit i = BK_i).
pub fn count_sigs<S: AsRef<[u8]>>(
    digest: &[u8; 32],
    sigs: &[S],
    bridge_keys: &[Address; SIGNERS],
) -> Result<u8, SigError> {
    let mut seen = 0u8;
    for sig in sigs {
        let signer = recover(digest, sig.as_ref())?;
        let idx = bridge_keys
            .iter()
            .position(|k| *k == signer)
            .ok_or(SigError::UnknownSigner)?;
        let bit = 1u8 << idx;
        if seen & bit != 0 {
            return Err(SigError::DuplicateSigner);
        }
        seen |= bit;
    }
    if (seen.count_ones() as usize) < THRESHOLD {
        return Err(SigError::NotEnoughSignatures);
    }
    Ok(seen)
}

/// Signs `digest` with a bridge key: RFC 6979 nonce, low `s`, `v` ∈ {27, 28}. Production bridge
/// keys sign in an HSM (09 §2.2); this is the reference signer for tests, `vyrn-sim` and the
/// conformance vectors. `None` if `secret` is not a valid scalar.
pub fn sign(digest: &[u8; 32], secret: &[u8; 32]) -> Option<[u8; 65]> {
    let key = SigningKey::from_slice(secret).ok()?;
    let (sig, id) = key.sign_prehash_recoverable(digest);
    let (sig, id) = match sig.normalize_s() {
        n if n != sig => (n, RecoveryId::new(!id.is_y_odd(), id.is_x_reduced())),
        _ => (sig, id),
    };
    let mut out = [0u8; 65];
    out.get_mut(..64)?.copy_from_slice(&sig.to_bytes());
    *out.get_mut(64)? = 27u8.checked_add(id.to_byte())?;
    Some(out)
}

/// The address of a bridge or guardian secret key; `None` if `secret` is not a valid scalar.
pub fn address_of_secret(secret: &[u8; 32]) -> Option<Address> {
    SigningKey::from_slice(secret)
        .ok()
        .map(|k| address_of(k.verifying_key()))
}
