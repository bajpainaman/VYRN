//! Blocks: header bytes, `header_hash`, `seq_sig`, the two roots, assembly and the hash chain
//! (07 §2.2, §3.10, §6.1). Consensus on blocks is `vyrn-consensus`'s.
//!
//! # BlockHeader (190 bytes, little-endian, 01 §6.6 field order)
//!
//! ```text
//! off size field
//!   0   8  height
//!   8   4  epoch
//!  12   2  book
//!  14   8  first_step    previous header's last_step + 1 (1 in the first block of an epoch)
//!  22   8  last_step     first_step − 1 for a block with no step
//!  30  32  prev          header_hash(height − 1)
//!  62  32  order_root
//!  94  32  data_root
//! 126  64  seq_sig       Ed25519 (RFC 8032) by the sender's seq_key; zeros in a seal block
//! ```
//!
//! - `header_hash(h) = BLAKE3("vyrn v1 header" ‖ bytes[0..126])`.
//! - `seq_sig = Sign(seq_key, "vyrn      v1 block" ‖ bytes[0..126])`. The context has six
//!   spaces after "vyrn", byte for byte as 07 §3.10 writes it.
//! - `order_root = BLAKE3(BLAKE3(order bytes A) ‖ BLAKE3(order bytes B))`; with one substream,
//!   B's order bytes are empty.
//! - `data_root = BLAKE3(BLAKE3(H_A) ‖ BLAKE3(H_B))`, where `H_x` is the concatenation of the
//!   full 32-byte BLAKE3 of every packet of substream x's PacketRecords in the block, in
//!   O-order (Advance records have none).

use vyrn_types::{BlockHeader, BookId, Ed25519Sig, Epoch, Hash, Height, PubKey, StepId};

use vyrn_crypto::hash::hash;

use crate::leb::Reader;
use crate::stream::{HalfBlock, TenureStart};

pub const HEADER_BYTES: usize = 190;
/// The bytes `header_hash` and `seq_sig` cover.
pub const HEADER_SIGNED_BYTES: usize = 126;
pub const HEADER_HASH_CONTEXT: &[u8] = b"vyrn v1 header";
pub const SEQ_SIG_CONTEXT: &[u8] = b"vyrn      v1 block";

pub fn encode_header(h: &BlockHeader) -> [u8; HEADER_BYTES] {
    let mut out = Vec::with_capacity(HEADER_BYTES);
    out.extend_from_slice(&h.height.0.to_le_bytes());
    out.extend_from_slice(&h.epoch.0.to_le_bytes());
    out.extend_from_slice(&h.book.0.to_le_bytes());
    out.extend_from_slice(&h.first_step.0.to_le_bytes());
    out.extend_from_slice(&h.last_step.0.to_le_bytes());
    out.extend_from_slice(&h.prev.0);
    out.extend_from_slice(&h.order_root.0);
    out.extend_from_slice(&h.data_root.0);
    out.extend_from_slice(&h.seq_sig);
    let mut b = [0u8; HEADER_BYTES];
    b.iter_mut().zip(&out).for_each(|(d, s)| *d = *s);
    b
}

/// Every 190-byte string is a header; the checks are [`check_link`] and [`verify_seq_sig`].
pub fn decode_header(b: &[u8; HEADER_BYTES]) -> BlockHeader {
    let mut r = Reader::new(b);
    // The reads cannot fail on 190 bytes; the defaults are unreachable.
    BlockHeader {
        height: Height(r.u64().unwrap_or_default()),
        epoch: Epoch(r.u32().unwrap_or_default()),
        book: BookId(r.u16().unwrap_or_default()),
        first_step: StepId(r.u64().unwrap_or_default()),
        last_step: StepId(r.u64().unwrap_or_default()),
        prev: Hash(r.array().unwrap_or_default()),
        order_root: Hash(r.array().unwrap_or_default()),
        data_root: Hash(r.array().unwrap_or_default()),
        seq_sig: r.array().unwrap_or([0; 64]),
    }
}

fn signed_part(h: &BlockHeader) -> [u8; HEADER_SIGNED_BYTES] {
    let full = encode_header(h);
    let mut b = [0u8; HEADER_SIGNED_BYTES];
    b.iter_mut().zip(&full).for_each(|(d, s)| *d = *s);
    b
}

pub fn header_hash(h: &BlockHeader) -> Hash {
    let mut m = HEADER_HASH_CONTEXT.to_vec();
    m.extend_from_slice(&signed_part(h));
    hash(&m)
}

/// The message `seq_sig` signs.
pub fn signing_message(h: &BlockHeader) -> Vec<u8> {
    let mut m = SEQ_SIG_CONTEXT.to_vec();
    m.extend_from_slice(&signed_part(h));
    m
}

/// `h` with `seq_sig` set by the 32-byte Ed25519 secret `seed`.
pub fn sign_header(h: &BlockHeader, seed: &[u8; 32]) -> BlockHeader {
    BlockHeader {
        seq_sig: vyrn_crypto::ed25519::sign(seed, &signing_message(h)),
        ..*h
    }
}

/// ZIP-215 verification of `seq_sig` under `seq_key` (11 §2.5).
pub fn verify_seq_sig(h: &BlockHeader, seq_key: &PubKey) -> bool {
    vyrn_crypto::ed25519::verify(seq_key, &signing_message(h), &h.seq_sig)
}

/// The seal-block signature: 64 zero bytes (07 §3.10).
pub const SEAL_SIG: Ed25519Sig = [0; 64];

fn pair(a: Hash, b: Hash) -> Hash {
    let mut m = [0u8; 64];
    m.iter_mut()
        .zip(a.0.iter().chain(&b.0))
        .for_each(|(d, s)| *d = *s);
    hash(&m)
}

pub fn order_root(order_a: &[u8], order_b: &[u8]) -> Hash {
    pair(hash(order_a), hash(order_b))
}

pub fn data_root(full_a: &[Hash], full_b: &[Hash]) -> Hash {
    let half = |hs: &[Hash]| hash(&hs.iter().flat_map(|h| h.0).collect::<Vec<u8>>());
    pair(half(full_a), half(full_b))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("height is not the previous height + 1")]
    Height,
    #[error("prev is not header_hash of the previous header")]
    Prev,
    #[error("first_step does not follow the previous last_step, or last_step < first_step - 1")]
    Steps,
    #[error("book differs from the previous header's")]
    Book,
    #[error("epoch is neither the previous epoch nor the next")]
    Epoch,
    #[error("seq_sig does not verify")]
    Sig,
    #[error("the two substreams closed different blocks, or the hashes do not match the packets")]
    Assembly,
}

/// The link from `prev` to `next` (07 §3.10, §6.4 item 1). Within an epoch,
/// `next.first_step = prev.last_step + 1`; the first block of epoch `e + 1` has
/// `first_step = 1`, because StepId restarts each epoch (01 §3).
pub fn check_link(prev: &BlockHeader, next: &BlockHeader) -> Result<(), ChainError> {
    check_anchor(header_hash(prev), prev.height, next)?;
    if next.book != prev.book {
        return Err(ChainError::Book);
    }
    let first = if next.epoch == prev.epoch {
        prev.last_step.0.checked_add(1)
    } else if Some(next.epoch.0) == prev.epoch.0.checked_add(1) {
        Some(1)
    } else {
        return Err(ChainError::Epoch);
    };
    if Some(next.first_step.0) != first {
        return Err(ChainError::Steps);
    }
    Ok(())
}

/// The link from an anchor known only by hash and height, such as a `TenureStart`'s
/// `prev_header_hash` or a `HandoffRecord`'s `log_hash`.
pub fn check_anchor(
    prev_hash: Hash,
    prev_height: Height,
    next: &BlockHeader,
) -> Result<(), ChainError> {
    if Some(next.height.0) != prev_height.0.checked_add(1) {
        return Err(ChainError::Height);
    }
    if next.prev != prev_hash {
        return Err(ChainError::Prev);
    }
    if next
        .last_step
        .0
        .checked_add(1)
        .is_none_or(|e| e < next.first_step.0)
    {
        return Err(ChainError::Steps);
    }
    Ok(())
}

/// Builds unsigned headers from closed half-blocks, one height at a time (core 50 and core 4 on
/// the sequencer; every replica to check a received header).
#[derive(Clone, Debug)]
pub struct BlockAssembler {
    epoch: Epoch,
    book: BookId,
    next_height: u64,
    next_first_step: u64,
    prev: Hash,
}

impl BlockAssembler {
    /// Starts at a tenure's first block (07 §3.9).
    pub fn from_tenure(book: BookId, ts: &TenureStart) -> Self {
        Self {
            epoch: ts.epoch,
            book,
            next_height: ts.first_height.0,
            next_first_step: ts.first_step.0,
            prev: ts.prev_header_hash,
        }
    }

    pub const fn next_height(&self) -> Height {
        Height(self.next_height)
    }

    /// The unsigned header (zero `seq_sig`) of the next block. `b` is `None` with one
    /// substream. `full_a` and `full_b` are the full packet hashes of `a.packets` and
    /// `b.packets`, in order.
    pub fn assemble(
        &mut self,
        a: &HalfBlock,
        b: Option<&HalfBlock>,
        full_a: &[Hash],
        full_b: &[Hash],
    ) -> Result<BlockHeader, ChainError> {
        let b_ok = b.is_none_or(|b| b.height == a.height && b.last_step == a.last_step);
        let nb = b.map_or(0, |b| b.packets.len());
        if a.height.0 != self.next_height
            || !b_ok
            || full_a.len() != a.packets.len()
            || full_b.len() != nb
        {
            return Err(ChainError::Assembly);
        }
        if a.last_step
            .0
            .checked_add(1)
            .is_none_or(|e| e < self.next_first_step)
        {
            return Err(ChainError::Steps);
        }
        let h = BlockHeader {
            height: a.height,
            epoch: self.epoch,
            book: self.book,
            first_step: StepId(self.next_first_step),
            last_step: a.last_step,
            prev: self.prev,
            order_root: order_root(&a.order_bytes, b.map_or(&[], |b| &b.order_bytes)),
            data_root: data_root(full_a, full_b),
            seq_sig: [0; 64],
        };
        self.prev = header_hash(&h);
        self.next_height = self.next_height.saturating_add(1);
        self.next_first_step = a.last_step.0.saturating_add(1);
        Ok(h)
    }
}
