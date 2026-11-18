//! The lane's session table (04 §4.1, §4.2): one slot per `SessionId` slot bits, owned by its
//! lane (`INV-WRITER`). Opening and closing sessions is the control path's (04 §4.4); the lane
//! only reads keys and advances `expected` and `next_resp`.

use vyrn_risk::{AcctSlot, SessionBuckets};
use vyrn_types::{BookId, LaneSeq, MAX_SESSIONS_PER_LANE, SessionId};
use vyrn_wire::{session_generation, session_slot};

/// 04 §4.3 states the lane distinguishes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessState {
    #[default]
    Free,
    Open,
    /// `New` and `Replace` fail `SESSION_CLOSED` (`PROTO_D_DRAINING`), cancels work (04 M4).
    Draining,
    Closed,
}

/// What the control path installs when it opens a session.
#[derive(Clone, Copy, Debug)]
pub struct SessionSpec {
    pub id: SessionId,
    pub acct: AcctSlot,
    /// `K_seq(e, this box)` (04 §4.6).
    pub k_seq: [u8; 16],
    pub book: BookId,
    pub buckets: SessionBuckets,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Session {
    pub id: SessionId,
    pub state: SessState,
    pub acct: AcctSlot,
    pub k_seq: [u8; 16],
    pub book: BookId,
    pub buckets: SessionBuckets,
    /// Next `pkt_seq` to accept (04 §5.1), from 1.
    pub expected: u32,
    /// Next in-stream `resp_seq` (04 §5.3), from 1.
    pub next_resp: u32,
    /// The `PROTO_D_*` close cause once `Closed` (04 §4.3): the detail of V7's
    /// out-of-stream `SESSION_CLOSED`.
    pub close_cause: u32,
    /// The newest `CancelAll` of this session; orders whose current version precedes it are
    /// ended in lane order (resolve answers `TOO_LATE`).
    pub cancel_all: LaneSeq,
    /// Roots of this session in creation order (= ascending handle order: slots are taken in
    /// index order), as an intrusive list over `RootP`.
    pub first: u32,
    pub last: u32,
}

pub(crate) struct Sessions {
    slots: Vec<Session>,
}

impl Sessions {
    pub fn new() -> Self {
        Self {
            slots: vec![Session::default(); MAX_SESSIONS_PER_LANE],
        }
    }

    fn ix(id: SessionId) -> usize {
        usize::from(session_slot(id))
    }

    pub fn open(&mut self, s: &SessionSpec) -> bool {
        let Some(x) = self.slots.get_mut(Self::ix(s.id)) else {
            return false;
        };
        if x.state != SessState::Free {
            return false;
        }
        *x = Session {
            id: s.id,
            state: SessState::Open,
            acct: s.acct,
            k_seq: s.k_seq,
            book: s.book,
            buckets: s.buckets,
            expected: 1,
            next_resp: 1,
            ..Session::default()
        };
        true
    }

    /// 04 V2: the slot is in use and its generation matches. The lane bits are checked by the
    /// caller.
    pub fn find(&self, id: SessionId) -> Option<u16> {
        let s = self.slots.get(Self::ix(id))?;
        (s.state != SessState::Free
            && session_generation(s.id) == session_generation(id)
            && s.id == id)
            .then(|| session_slot(id))
    }

    pub fn get(&self, ix: u16) -> Option<&Session> {
        self.slots.get(usize::from(ix))
    }

    pub fn get_mut(&mut self, ix: u16) -> Option<&mut Session> {
        self.slots.get_mut(usize::from(ix))
    }
}
