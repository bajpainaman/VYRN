//! Data box failover (07 §5.7): the backup home rule (step 2) and the `DataRedirect` record a
//! live data box sends to each affected session's address (step 3).
//!
//! *Reading (recorded in 07 §5.7):* 04 owns `DataRedirect` but gives no bytes. This crate fixes
//! them, 24 bytes, little-endian:
//!
//! ```text
//! off size field
//!   0   2  magic 0x5244 ("DR")    2 1 version 1     3 1 down (d)     4 1 to (d')    5 3 reserved 0
//!   8   4  session                12 4 resend_from
//!  16   8  tag = SipHash-2-4(K, bytes 0..16), K = the session's K_seq (BASE) or K_com (CHAIN)
//! ```
//!
//! The tag uses the key the session already signs its packets with, so the client can check
//! that a redirect comes from a box that holds its key; a forged redirect only moves copy 2,
//! which every replica re-hashes (07 §5.4).

use vyrn_types::{SessionId, Tag};

pub const MAGIC: u16 = 0x5244;
pub const VERSION: u8 = 1;
pub const BYTES: usize = 24;

/// `DataRedirect{d → d', resend_from}` for one session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirect {
    pub down: u8,
    pub to: u8,
    pub session: SessionId,
    /// The lowest `pkt_seq` no replica has resolved; the client resends from here.
    pub resend_from: u32,
}

/// Why a redirect was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RedirectErr {
    #[error("not 24 bytes")]
    Short,
    #[error("bad magic")]
    Magic,
    #[error("bad version")]
    Version,
    #[error("reserved bytes are not zero")]
    Reserved,
    #[error("the tag does not verify")]
    Tag,
}

impl Redirect {
    pub fn seal(&self, key: &[u8; 16]) -> [u8; BYTES] {
        let mut b = [0u8; BYTES];
        b[0..2].copy_from_slice(&MAGIC.to_le_bytes());
        b[2] = VERSION;
        b[3] = self.down;
        b[4] = self.to;
        b[8..12].copy_from_slice(&self.session.0.to_le_bytes());
        b[12..16].copy_from_slice(&self.resend_from.to_le_bytes());
        let tag = vyrn_crypto::siphash24(key, &b[..16]);
        b[16..24].copy_from_slice(&tag.0.to_le_bytes());
        b
    }

    /// Checks the tag first, in constant time, then the fields.
    pub fn open(b: &[u8], key: &[u8; 16]) -> Result<Self, RedirectErr> {
        let b: &[u8; BYTES] = b.try_into().map_err(|_| RedirectErr::Short)?;
        let (body, tag) = b.split_at(16);
        let mut t = [0u8; 8];
        t.copy_from_slice(tag);
        if !vyrn_crypto::siphash::verify(key, body, Tag(u64::from_le_bytes(t))) {
            return Err(RedirectErr::Tag);
        }
        if u16::from_le_bytes([b[0], b[1]]) != MAGIC {
            return Err(RedirectErr::Magic);
        }
        if b[2] != VERSION {
            return Err(RedirectErr::Version);
        }
        if b[5..8] != [0; 3] {
            return Err(RedirectErr::Reserved);
        }
        let u = |a: usize| u32::from_le_bytes([b[a], b[a + 1], b[a + 2], b[a + 3]]);
        Ok(Self {
            down: b[3],
            to: b[4],
            session: SessionId(u(8)),
            resend_from: u(12),
        })
    }
}

/// 07 §5.7 step 2: the backup home of a session homed on `down` is the next live box after it
/// in facility order, wrapping; `live[i]` says whether box `i` is up. `None` if no other box is
/// live. Every box and replica computes the same answer, so no message chooses it.
pub fn backup_home(down: u8, live: &[bool]) -> Option<u8> {
    let n = live.len();
    (1..n)
        .map(|k| (usize::from(down) + k) % n)
        .find(|&i| live.get(i).copied().unwrap_or(false))
        .and_then(|i| u8::try_from(i).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_home_is_the_next_live_box_wrapping() {
        let live = [true, false, false, true, false];
        assert_eq!(backup_home(1, &live), Some(3));
        assert_eq!(backup_home(3, &live), Some(0), "wraps past the end");
        assert_eq!(backup_home(0, &[true, false]), None, "no other live box");
        // The down box itself never counts, even if `live` still says up.
        assert_eq!(backup_home(2, &[false, false, true]), None);
    }
}
