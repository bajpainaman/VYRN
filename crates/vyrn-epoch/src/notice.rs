//! When a lane sends `EpochNotice` (08 §2.4).
//!
//! A [`Notifier`] runs per lane. It sees each packet's logged `rx_ts` in lane order and returns
//! at most one in-stream notice per packet:
//!
//! 1. the first packet with `rx_ts ≥ T` gets the seal notice (seconds 0), and nothing after it;
//! 2. else the first packet after a revision gets a notice with flags bit0 (revised);
//! 3. else the first packet with `rx_ts ≥ T − offset`, for the largest offset of
//!    `EPO_NOTICE_OFFSETS_S` not yet sent, gets a notice. Offsets crossed together send one notice.
//!
//! Seconds are `ceil((T − rx_ts) / 1 s)`. The trigger is a logged `rx_ts`, never a timer, so
//! replicas reproduce every notice bit for bit (`INV-DET`). The session-open notice and the
//! out-of-stream notice of a sealed old home come from [`Notifier::current`] and
//! [`Notifier::redirect`].
//!
//! The wire record is `vyrn-wire`'s `Record::EpochNotice`. Spec gap: 01 §6.4 still writes bytes
//! 1–3 as zero; 08 Requests to 01 item 1 puts `seq_index` and the flags there. [`EpochNotice`]
//! carries both, and an encoder that follows merged 01 drops them.

use crate::schedule::Boundary;
use crate::{EPO_NOTICE_OFFSETS_S, NS_PER_S};
use vyrn_types::{Epoch, HomeCode, Nanos};

/// `EpochNotice` flag bits (08 §2.4, Requests to 01 item 1).
pub struct NoticeFlags;

impl NoticeFlags {
    pub const REVISED: u16 = 1 << 0;
    pub const HOLD: u16 = 1 << 1;
    pub const SKIP: u16 = 1 << 2;
    pub const DATE_ROLL: u16 = 1 << 3;
    pub const ENDPOINTS: u16 = 1 << 4;
}

/// The content of one `EpochNotice` record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochNotice {
    pub next: Epoch,
    pub home: HomeCode,
    /// Whole seconds to T, rounded up; 0 at and after the seal.
    pub secs: u32,
    /// `seq_index` of the next epoch's primary.
    pub seq_index: u8,
    pub flags: u16,
}

/// One lane's notice trigger for one boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notifier {
    next: Epoch,
    home: HomeCode,
    t: Nanos,
    seq_index: u8,
    /// Index into `EPO_NOTICE_OFFSETS_S` of the next offset not yet sent.
    offset: usize,
    /// Flags of a revision whose notice is still to send.
    revision: Option<u16>,
    sealed: bool,
}

impl Notifier {
    /// A trigger for `boundary` that has sent nothing yet.
    pub fn new(boundary: &Boundary, seq_index: u8) -> Self {
        Self {
            next: boundary.to,
            home: boundary.to_home,
            t: boundary.t,
            seq_index,
            offset: 0,
            revision: None,
            sealed: false,
        }
    }

    /// The schedule changed (hold, skip, override or sequencer change) at a record logged at
    /// `at`. The next packet gets a revised notice with `flags` | `REVISED`, and offsets the
    /// revised T has already passed at `at` are not sent again.
    pub fn revise(&mut self, boundary: &Boundary, seq_index: u8, flags: u16, at: Nanos) {
        self.next = boundary.to;
        self.home = boundary.to_home;
        self.t = boundary.t;
        self.seq_index = seq_index;
        self.revision = Some(flags | NoticeFlags::REVISED);
        self.offset = self.crossed_from(0, at);
    }

    /// The in-stream notice this lane sends with its packet at `rx_ts`, if any.
    pub fn on_packet(&mut self, rx_ts: Nanos) -> Option<EpochNotice> {
        if self.sealed {
            return None;
        }
        if rx_ts >= self.t {
            self.sealed = true;
            self.revision = None;
            self.offset = EPO_NOTICE_OFFSETS_S.len();
            return Some(self.notice(rx_ts, 0));
        }
        if let Some(flags) = self.revision.take() {
            self.offset = self.crossed_from(self.offset, rx_ts);
            return Some(self.notice(rx_ts, flags));
        }
        let crossed = self.crossed_from(self.offset, rx_ts);
        if crossed == self.offset {
            return None;
        }
        self.offset = crossed;
        Some(self.notice(rx_ts, 0))
    }

    /// The notice as of `rx_ts` without consuming a trigger: the session-open notice.
    pub fn current(&self, rx_ts: Nanos) -> EpochNotice {
        self.notice(rx_ts, 0)
    }

    /// The out-of-stream notice of a sealed old home for a stray packet (08 §10.7).
    pub fn redirect(&self) -> EpochNotice {
        self.notice(self.t, 0)
    }

    pub fn sealed(&self) -> bool {
        self.sealed
    }

    /// The first offset index at or after `from` whose threshold `T − offset` is after `rx_ts`.
    fn crossed_from(&self, from: usize, rx_ts: Nanos) -> usize {
        let mut i = from;
        while let Some(&off) = EPO_NOTICE_OFFSETS_S.get(i) {
            if rx_ts.0 < self.t.0.saturating_sub(off * NS_PER_S) {
                break;
            }
            i += 1;
        }
        i
    }

    fn notice(&self, rx_ts: Nanos, flags: u16) -> EpochNotice {
        let left = self.t.0.saturating_sub(rx_ts.0);
        let secs = u32::try_from(left.div_ceil(NS_PER_S)).unwrap_or(u32::MAX);
        EpochNotice {
            next: self.next,
            home: self.home,
            secs,
            seq_index: self.seq_index,
            flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Nanos = Nanos(100_000 * NS_PER_S);

    fn boundary(t: Nanos) -> Boundary {
        Boundary {
            from: Epoch(3),
            to: Epoch(4),
            t,
            from_home: HomeCode::Tyo,
            to_home: HomeCode::Ldn,
        }
    }

    fn before(s: u64, ns: u64) -> Nanos {
        Nanos(T.0 - s * NS_PER_S + ns)
    }

    #[test]
    fn offsets_fire_once_on_the_first_packet_past_them() {
        let mut n = Notifier::new(&boundary(T), 2);
        assert_eq!(n.on_packet(before(3_601, 0)), None);
        let first = n.on_packet(before(3_600, 0)).map(|x| x.secs);
        assert_eq!(first, Some(3_600));
        assert_eq!(n.on_packet(before(3_000, 0)), None);
        // 1 ns past T − 600 s: 599.999… s left, rounded up to 600.
        assert_eq!(n.on_packet(before(600, 1)).map(|x| x.secs), Some(600));
        // A quiet session's next packet is at T: the seal notice replaces 60, 10 and 1 s.
        assert_eq!(n.on_packet(before(0, 0)).map(|x| x.secs), Some(0));
        assert!(n.sealed());
        assert_eq!(n.on_packet(Nanos(T.0 + 5)), None);
        assert_eq!(n.redirect().secs, 0);
    }

    #[test]
    fn crossed_offsets_collapse_into_one_notice() {
        let mut n = Notifier::new(&boundary(T), 0);
        assert_eq!(n.on_packet(before(5, 0)).map(|x| x.secs), Some(5));
        assert_eq!(n.on_packet(before(2, 0)), None);
        assert_eq!(n.on_packet(before(1, 0)).map(|x| x.secs), Some(1));
        assert_eq!(n.on_packet(before(0, 0)).map(|x| x.secs), Some(0));
    }

    #[test]
    fn a_hold_sends_a_revised_notice_and_rearms_the_offsets() {
        let mut n = Notifier::new(&boundary(T), 0);
        assert!(n.on_packet(before(10, 0)).is_some());
        let held = Nanos(T.0 + 900 * NS_PER_S);
        n.revise(&boundary(held), 1, NoticeFlags::HOLD, before(9, 0));
        let r = n.on_packet(before(8, 0));
        assert_eq!(
            r,
            Some(EpochNotice {
                next: Epoch(4),
                home: HomeCode::Ldn,
                secs: 908,
                seq_index: 1,
                flags: NoticeFlags::HOLD | NoticeFlags::REVISED,
            })
        );
        // 600 s before the new T fires again; the old T is no longer a seal.
        assert_eq!(n.on_packet(T), None);
        assert_eq!(
            n.on_packet(Nanos(held.0 - 600 * NS_PER_S)).map(|x| x.secs),
            Some(600)
        );
    }
}
