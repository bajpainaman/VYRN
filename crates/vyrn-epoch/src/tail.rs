//! The log tail over the WAN (08 §5.5): what a follower home holds of epoch e, what it is
//! missing, and the `EpoTailReq` / `EpoTailResp` pull.
//!
//! The tail moves by streaming: two relays in the old home forward every order frame on both WAN
//! paths, every member of `R_e` sends block finality certificates and `HandoffSig`, and the data
//! tier sends every payload on both paths. A follower replays unfinalized frames speculatively
//! and treats state as final only up to the last finalized block. A pull is needed only when both
//! paths lost the same data (two faults, §10.6).
//!
//! | Type | Role |
//! |---|---|
//! | [`TailFollow`] | the heights a follower holds, which are final, the speculative frontier, the gaps below `last_height` |
//! | [`EpoTailReq`], [`TailWant`] | the pull: missing heights or payload hashes, sent to the old and third homes at once |
//! | [`TailPull`] | one outstanding pull: the first `EpoTailResp` from either source wins, later ones are ignored |
//!
//! A response needs no signature of its own: a block carries its finality certificate and a
//! payload its `PktHash`, so the receiver checks what it got against what it asked for, not who
//! sent it. [`TailPull::on_resp`] only decides which response to use; the caller verifies it.
//!
//! Spec gaps [Guessing]: 08 gives `EpoTailReq{heights | pkt_hashes}` without bytes or a request
//! id. This crate encodes it as `book u16 ‖ epoch u32 ‖ req_id u32 ‖ kind u8 (1 heights,
//! 2 pkt_hashes) ‖ count u16 ‖ count × u64`, little-endian, at most [`EPO_TAIL_REQ_MAX`] items.
//! **Flag: new wire layout.**

use std::collections::BTreeSet;
use thiserror::Error;
use vyrn_types::{BookId, Epoch, Height, PktHash};

/// Items per `EpoTailReq` (spec gap: 08 names no bound) [Guessing].
pub const EPO_TAIL_REQ_MAX: usize = 1_024;
const HEADER_BYTES: usize = 2 + 4 + 4 + 1 + 2;

/// What a follower holds of epoch e above its last snapshot or certified start.
///
/// A finality certificate for a block also finalizes every ancestor (07 §2.1), so the follower
/// keeps one certified frontier, not one flag per height: state is final through the contiguous
/// held prefix up to that frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailFollow {
    /// Every height at or below this is held and final.
    final_height: Height,
    /// Held above `final_height`, finalized or not.
    held: BTreeSet<u64>,
    /// The highest height with a finality certificate seen, held or not.
    certified: Height,
}

impl TailFollow {
    /// A follower whose log is final through `base`.
    pub fn new(base: Height) -> Self {
        Self {
            final_height: base,
            held: BTreeSet::new(),
            certified: base,
        }
    }

    /// A block's frames arrived (speculative until a certificate at or above it).
    pub fn on_block(&mut self, h: Height) {
        if h > self.final_height {
            self.held.insert(h.0);
        }
        self.advance();
    }

    /// A finality certificate for `h` arrived: `h` and every ancestor are final. Heights the
    /// follower does not hold yet become final once their frames arrive.
    pub fn on_final(&mut self, h: Height) {
        self.certified = self.certified.max(h);
        self.advance();
    }

    fn advance(&mut self) {
        while self.final_height < self.certified && self.held.remove(&(self.final_height.0 + 1)) {
            self.final_height = Height(self.final_height.0 + 1);
        }
    }

    /// The last height whose state this follower may treat as final (§5.5).
    pub fn final_height(&self) -> Height {
        self.final_height
    }

    /// The speculative frontier: the highest contiguous held height. The replay may run to here.
    pub fn spec_height(&self) -> Height {
        let mut h = self.final_height.0;
        while self.held.contains(&(h + 1)) {
            h += 1;
        }
        Height(h)
    }

    /// What check 4 of §5.4 waits for before `last_height` (the certificate's) is final here:
    /// every height through it that this follower does not hold, and `last_height` itself when
    /// no certificate at or above it has arrived (its certificate finalizes the rest). Ascending,
    /// at most `max`.
    pub fn missing(&self, last_height: Height, max: usize) -> Vec<Height> {
        let uncertified = self.certified < last_height;
        (self.final_height.0 + 1..=last_height.0)
            .filter(|h| !self.held.contains(h) || (uncertified && *h == last_height.0))
            .take(max)
            .map(Height)
            .collect()
    }
}

/// What an `EpoTailReq` asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TailWant {
    Heights(Vec<Height>),
    Payloads(Vec<PktHash>),
}

/// `EpoTailReq` (§5.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpoTailReq {
    pub book: BookId,
    pub epoch: Epoch,
    /// Chosen by the requester; the response echoes it.
    pub req_id: u32,
    pub want: TailWant,
}

/// Why `EpoTailReq` bytes do not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TailErr {
    #[error("wrong length")]
    Length,
    #[error("unknown kind {0}")]
    Kind(u8),
    #[error("{0} items, at most EPO_TAIL_REQ_MAX")]
    TooMany(usize),
    #[error("an empty request")]
    Empty,
}

impl EpoTailReq {
    pub fn encode(&self) -> Result<Vec<u8>, TailErr> {
        let (kind, items): (u8, Vec<u64>) = match &self.want {
            TailWant::Heights(h) => (1, h.iter().map(|h| h.0).collect()),
            TailWant::Payloads(p) => (2, p.iter().map(|p| p.0).collect()),
        };
        if items.is_empty() {
            return Err(TailErr::Empty);
        }
        let count = u16::try_from(items.len())
            .ok()
            .filter(|&c| usize::from(c) <= EPO_TAIL_REQ_MAX)
            .ok_or(TailErr::TooMany(items.len()))?;
        let mut b = Vec::with_capacity(HEADER_BYTES + 8 * items.len());
        b.extend_from_slice(&self.book.0.to_le_bytes());
        b.extend_from_slice(&self.epoch.0.to_le_bytes());
        b.extend_from_slice(&self.req_id.to_le_bytes());
        b.push(kind);
        b.extend_from_slice(&count.to_le_bytes());
        for i in items {
            b.extend_from_slice(&i.to_le_bytes());
        }
        Ok(b)
    }

    pub fn decode(b: &[u8]) -> Result<Self, TailErr> {
        let (head, body) = b.split_at_checked(HEADER_BYTES).ok_or(TailErr::Length)?;
        let count = usize::from(u16::from_le_bytes([head[11], head[12]]));
        if count == 0 {
            return Err(TailErr::Empty);
        }
        if count > EPO_TAIL_REQ_MAX {
            return Err(TailErr::TooMany(count));
        }
        if body.len() != 8 * count {
            return Err(TailErr::Length);
        }
        let items = body
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c));
        let want = match head[10] {
            1 => TailWant::Heights(items.map(Height).collect()),
            2 => TailWant::Payloads(items.map(PktHash).collect()),
            k => return Err(TailErr::Kind(k)),
        };
        Ok(Self {
            book: BookId(u16::from_le_bytes([head[0], head[1]])),
            epoch: Epoch(u32::from_le_bytes([head[2], head[3], head[4], head[5]])),
            req_id: u32::from_le_bytes([head[6], head[7], head[8], head[9]]),
            want,
        })
    }
}

/// Where a pull goes: both at once (§5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailSource {
    OldHome,
    ThirdHome,
}

/// What to do with one `EpoTailResp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespVerdict {
    /// The first response to the outstanding request: verify and use it.
    Use,
    /// A later or unknown response: ignore it.
    Ignore,
}

/// One outstanding pull. The first `EpoTailResp` from either source wins (§5.5).
///
/// If the winning response fails the caller's verification, the caller calls
/// [`TailPull::reject`] and the other source's response is used instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailPull {
    req_id: u32,
    won: Option<TailSource>,
    rejected: Vec<TailSource>,
}

impl TailPull {
    pub fn new(req: &EpoTailReq) -> Self {
        Self {
            req_id: req.req_id,
            won: None,
            rejected: Vec::new(),
        }
    }

    /// The sources to send the request to, at the same time.
    pub fn targets() -> [TailSource; 2] {
        [TailSource::OldHome, TailSource::ThirdHome]
    }

    pub fn on_resp(&mut self, from: TailSource, req_id: u32) -> RespVerdict {
        if req_id != self.req_id || self.won.is_some() || self.rejected.contains(&from) {
            return RespVerdict::Ignore;
        }
        self.won = Some(from);
        RespVerdict::Use
    }

    /// The response from `from` did not verify: reopen the pull for the other source.
    pub fn reject(&mut self, from: TailSource) {
        if self.won == Some(from) {
            self.won = None;
        }
        if !self.rejected.contains(&from) {
            self.rejected.push(from);
        }
    }

    /// The source whose response is in use, if any.
    pub fn winner(&self) -> Option<TailSource> {
        self.won
    }

    /// Both sources failed: the pull must be sent again (or the book halts, §10.3).
    pub fn exhausted(&self) -> bool {
        self.rejected.len() == Self::targets().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follow_separates_final_from_speculative() {
        let mut f = TailFollow::new(Height(10));
        for h in [11, 12, 13, 15] {
            f.on_block(Height(h));
        }
        assert_eq!(
            (f.final_height(), f.spec_height()),
            (Height(10), Height(13))
        );
        assert_eq!(f.missing(Height(15), 10), [Height(14), Height(15)]);
        // One certificate at 12 finalizes 11 and 12 (07 §2.1).
        f.on_final(Height(12));
        assert_eq!(f.final_height(), Height(12));
        // A certificate at 15 above a gap at 14 finalizes only through 13.
        f.on_final(Height(15));
        assert_eq!(
            (f.final_height(), f.spec_height()),
            (Height(13), Height(13))
        );
        assert_eq!(f.missing(Height(15), 10), [Height(14)]);
        assert_eq!(f.missing(Height(16), 1), [Height(14)]);
        // A certificate that arrived before the frames counts once they arrive.
        f.on_block(Height(14));
        assert_eq!(
            (f.final_height(), f.spec_height()),
            (Height(15), Height(15))
        );
        assert_eq!(f.missing(Height(15), 10), Vec::<Height>::new());
        // Held but uncertified: the last height's certificate is what is missing.
        f.on_block(Height(16));
        assert_eq!(f.missing(Height(16), 10), [Height(16)]);
        // Anything at or below the final height is ignored.
        f.on_block(Height(3));
        f.on_final(Height(4));
        assert_eq!(f.final_height(), Height(15));
    }

    #[test]
    fn request_round_trips_and_rejects_malformed_bytes() {
        let req = EpoTailReq {
            book: BookId(0x0102),
            epoch: Epoch(7),
            req_id: 0xA1B2_C3D4,
            want: TailWant::Heights(vec![Height(41), Height(42)]),
        };
        let b = req.encode().unwrap_or_default();
        assert_eq!(b.len(), HEADER_BYTES + 16);
        assert_eq!(
            &b[..13],
            &[2, 1, 7, 0, 0, 0, 0xD4, 0xC3, 0xB2, 0xA1, 1, 2, 0]
        );
        assert_eq!(EpoTailReq::decode(&b), Ok(req.clone()));
        let pay = EpoTailReq {
            want: TailWant::Payloads(vec![PktHash(u64::MAX)]),
            ..req.clone()
        };
        assert_eq!(
            EpoTailReq::decode(&pay.encode().unwrap_or_default()),
            Ok(pay)
        );
        assert_eq!(EpoTailReq::decode(&b[..b.len() - 1]), Err(TailErr::Length));
        let mut k = b.clone();
        k[10] = 3;
        assert_eq!(EpoTailReq::decode(&k), Err(TailErr::Kind(3)));
        let empty = EpoTailReq {
            want: TailWant::Heights(vec![]),
            ..req.clone()
        };
        assert_eq!(empty.encode(), Err(TailErr::Empty));
        let big = EpoTailReq {
            want: TailWant::Heights(vec![Height(1); EPO_TAIL_REQ_MAX + 1]),
            ..req
        };
        assert_eq!(big.encode(), Err(TailErr::TooMany(EPO_TAIL_REQ_MAX + 1)));
    }

    #[test]
    fn the_first_response_wins_and_a_bad_one_reopens() {
        let req = EpoTailReq {
            book: BookId(1),
            epoch: Epoch(7),
            req_id: 9,
            want: TailWant::Heights(vec![Height(5)]),
        };
        let mut p = TailPull::new(&req);
        assert_eq!(p.on_resp(TailSource::ThirdHome, 8), RespVerdict::Ignore);
        assert_eq!(p.on_resp(TailSource::ThirdHome, 9), RespVerdict::Use);
        assert_eq!(p.on_resp(TailSource::OldHome, 9), RespVerdict::Ignore);
        // The third home's answer failed verification: the old home's later answer is used.
        p.reject(TailSource::ThirdHome);
        assert_eq!(p.on_resp(TailSource::ThirdHome, 9), RespVerdict::Ignore);
        assert_eq!(p.on_resp(TailSource::OldHome, 9), RespVerdict::Use);
        assert_eq!(p.winner(), Some(TailSource::OldHome));
        assert!(!p.exhausted());
        p.reject(TailSource::OldHome);
        assert!(p.exhausted());
    }
}
