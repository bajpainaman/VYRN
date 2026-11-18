//! The drop-copy session wire (10 §8.5): fixed 64-byte server frames, a 128-byte signed login,
//! and the subscription rule. Little-endian throughout.
//!
//! ```text
//! Frame (server → client, 64 B)
//!   0 1 kind     1 RECORD 2 HEARTBEAT 3 HELLO 4 ACCEPT 5 REJECT 6 END
//!   1 1 flags    0
//!   2 2 book     BookId
//!   4 4 epoch    Epoch of seq
//!   8 8 seq      RECORD: the record's stream seq; HEARTBEAT: the last seq sent;
//!                ACCEPT: the first seq that follows; END: the epoch's last seq; else 0
//!  16 48 body    RECORD: the record; HELLO: challenge (32) | 0; ACCEPT: the stream's
//!                newest seq (u64) | 0; REJECT: reason (u16) | 0; else 0
//!
//! Login (client → server, 128 B)
//!   0 4 magic    "VDC1"
//!   4 1 kind     1
//!   5 1 flags    bit 0: the master stream of `account`
//!   6 2 book
//!   8 4 account  the stream's account
//!  12 4 epoch    the epoch to start in (current or previous)
//!  16 8 from     first seq wanted, ≥ 1
//!  24 4 signer   the account whose key signs: `account`, or its master
//!  28 4 0
//!  32 32 challenge, as HELLO sent it
//!  64 64 Ed25519 signature over DC_LOGIN_CONTEXT || bytes 0..64
//! ```

use vyrn_types::{AccountId, BookId, Epoch};

use super::record::{DC_REC_BYTES, DcRecord};

pub const FRAME_BYTES: usize = 64;
pub const LOGIN_BYTES: usize = 128;
pub const LOGIN_MAGIC: [u8; 4] = *b"VDC1";
/// Domain of the login signature.
pub const DC_LOGIN_CONTEXT: &[u8] = b"vyrn v1 dropcopy login";
/// Idle time after which a stream sends a heartbeat (\[Guessing\], config).
pub const DC_HEARTBEAT_MS: u64 = 100;
/// Time a connection has to send its login after `HELLO` before the server drops it
/// (\[Guessing\], config).
pub const DC_LOGIN_TIMEOUT_MS: u64 = 5_000;
/// Time a write may block on a subscriber that does not drain its stream before the server
/// drops it (\[Guessing\], config).
pub const DC_WRITE_TIMEOUT_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Record = 1,
    Heartbeat = 2,
    Hello = 3,
    Accept = 4,
    Reject = 5,
    End = 6,
}

/// `REJECT` reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// Not a login: bad magic, kind, padding or length.
    Malformed = 1,
    /// Unknown signer, or the signature does not verify over this connection's challenge.
    Auth = 2,
    /// The signer may not read this stream (10 §8.5 rule 2).
    Denied = 3,
    /// Another book.
    Book = 4,
    /// The epoch is outside the replay window (`MD_DC_REPLAY_EPOCHS`).
    Epoch = 5,
    /// `from` is 0 or past the stream's newest seq + 1.
    Range = 6,
    /// No such stream.
    Stream = 7,
}

impl RejectReason {
    pub const fn from_code(c: u16) -> Option<Self> {
        Some(match c {
            1 => Self::Malformed,
            2 => Self::Auth,
            3 => Self::Denied,
            4 => Self::Book,
            5 => Self::Epoch,
            6 => Self::Range,
            7 => Self::Stream,
            _ => return None,
        })
    }
}

/// One server frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub book: BookId,
    pub epoch: Epoch,
    pub seq: u64,
    pub body: [u8; DC_REC_BYTES],
}

impl Frame {
    pub fn record(book: BookId, epoch: Epoch, seq: u64, r: &DcRecord) -> Self {
        Self {
            kind: FrameKind::Record,
            book,
            epoch,
            seq,
            body: r.0,
        }
    }

    pub fn bare(kind: FrameKind, book: BookId, epoch: Epoch, seq: u64) -> Self {
        Self {
            kind,
            book,
            epoch,
            seq,
            body: [0; DC_REC_BYTES],
        }
    }

    pub fn hello(book: BookId, epoch: Epoch, challenge: &[u8; 32]) -> Self {
        let mut f = Self::bare(FrameKind::Hello, book, epoch, 0);
        f.body[..32].copy_from_slice(challenge);
        f
    }

    pub fn accept(book: BookId, epoch: Epoch, first: u64, newest: u64) -> Self {
        let mut f = Self::bare(FrameKind::Accept, book, epoch, first);
        f.body[..8].copy_from_slice(&newest.to_le_bytes());
        f
    }

    pub fn reject(book: BookId, epoch: Epoch, why: RejectReason) -> Self {
        let mut f = Self::bare(FrameKind::Reject, book, epoch, 0);
        f.body[..2].copy_from_slice(&(why as u16).to_le_bytes());
        f
    }

    pub fn encode(&self) -> [u8; FRAME_BYTES] {
        let mut b = [0; FRAME_BYTES];
        b[0] = self.kind as u8;
        b[2..4].copy_from_slice(&self.book.0.to_le_bytes());
        b[4..8].copy_from_slice(&self.epoch.0.to_le_bytes());
        b[8..16].copy_from_slice(&self.seq.to_le_bytes());
        b[16..].copy_from_slice(&self.body);
        b
    }

    /// `None` for an unknown kind or a non-zero flags or padding byte.
    pub fn decode(b: &[u8; FRAME_BYTES]) -> Option<Self> {
        let kind = match b[0] {
            1 => FrameKind::Record,
            2 => FrameKind::Heartbeat,
            3 => FrameKind::Hello,
            4 => FrameKind::Accept,
            5 => FrameKind::Reject,
            6 => FrameKind::End,
            _ => return None,
        };
        if b[1] != 0 {
            return None;
        }
        let mut body = [0; DC_REC_BYTES];
        body.copy_from_slice(&b[16..]);
        let mut seq = [0; 8];
        seq.copy_from_slice(&b[8..16]);
        Some(Self {
            kind,
            book: BookId(u16::from_le_bytes([b[2], b[3]])),
            epoch: Epoch(u32::from_le_bytes([b[4], b[5], b[6], b[7]])),
            seq: u64::from_le_bytes(seq),
            body,
        })
    }

    /// The record of a `RECORD` frame.
    pub fn as_record(&self) -> Option<DcRecord> {
        (self.kind == FrameKind::Record)
            .then(|| DcRecord::decode(&self.body).ok())
            .flatten()
    }

    /// The reason of a `REJECT` frame.
    pub fn reason(&self) -> Option<RejectReason> {
        RejectReason::from_code(u16::from_le_bytes([self.body[0], self.body[1]]))
    }
}

/// A login request, before its signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Login {
    pub master: bool,
    pub book: BookId,
    pub account: AccountId,
    pub epoch: Epoch,
    pub from: u64,
    pub signer: AccountId,
    pub challenge: [u8; 32],
}

impl Login {
    /// Bytes 0..64, which the signature covers.
    pub fn body(&self) -> [u8; 64] {
        let mut b = [0; 64];
        b[0..4].copy_from_slice(&LOGIN_MAGIC);
        b[4] = 1;
        b[5] = u8::from(self.master);
        b[6..8].copy_from_slice(&self.book.0.to_le_bytes());
        b[8..12].copy_from_slice(&self.account.0.to_le_bytes());
        b[12..16].copy_from_slice(&self.epoch.0.to_le_bytes());
        b[16..24].copy_from_slice(&self.from.to_le_bytes());
        b[24..28].copy_from_slice(&self.signer.0.to_le_bytes());
        b[32..64].copy_from_slice(&self.challenge);
        b
    }

    /// The message the signer signs.
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = DC_LOGIN_CONTEXT.to_vec();
        m.extend_from_slice(&self.body());
        m
    }

    /// The 128-byte login, signed with the signer's Ed25519 seed.
    pub fn encode_signed(&self, seed: &[u8; 32]) -> [u8; LOGIN_BYTES] {
        let sig = vyrn_crypto::ed25519::sign(seed, &self.signed_message());
        let mut b = [0; LOGIN_BYTES];
        b[..64].copy_from_slice(&self.body());
        b[64..].copy_from_slice(&sig);
        b
    }

    /// The login and its signature; `None` for a malformed one. Does not verify.
    pub fn decode(b: &[u8; LOGIN_BYTES]) -> Option<(Self, [u8; 64])> {
        if b[0..4] != LOGIN_MAGIC || b[4] != 1 || b[5] & !1 != 0 || b[28..32] != [0; 4] {
            return None;
        }
        let u32_at = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let mut from = [0; 8];
        from.copy_from_slice(&b[16..24]);
        let mut challenge = [0; 32];
        challenge.copy_from_slice(&b[32..64]);
        let mut sig = [0; 64];
        sig.copy_from_slice(&b[64..]);
        Some((
            Self {
                master: b[5] & 1 != 0,
                book: BookId(u16::from_le_bytes([b[6], b[7]])),
                account: AccountId(u32_at(8)),
                epoch: Epoch(u32_at(12)),
                from: u64::from_le_bytes(from),
                signer: AccountId(u32_at(24)),
                challenge,
            },
            sig,
        ))
    }
}
