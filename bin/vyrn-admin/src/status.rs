//! The `DataTierStatus` push of 04 §4.4: which frames `vyrn-admin` sends to which session.
//!
//! [`StatusPush`] keeps, per session, the `KeyBundle.data` list and the last `seq` and `down` of
//! each epoch the session holds a bundle for: the current one and, once pushed, the next.
//!
//! - [`StatusPush::bundle`]: with every `KeyBundle` push and every `OpenSessionResp`, the epoch's
//!   snapshot as its `seq` 1.
//! - [`StatusPush::set_down`]: when Q replicas mark data boxes down or up (07 §5.7), one status
//!   for each session and epoch whose `down` mask changed, with the next `seq`. Sessions whose
//!   list does not contain a changed box get nothing.
//! - [`StatusPush::retire`]: drops an epoch once it is over.
//!
//! Down boxes are named by address, because the positions in `down` are per session (04 §4.4).
//! Cold path: pushes are rare.

use core::net::SocketAddrV4;
use std::collections::{BTreeMap, BTreeSet};

use vyrn_types::{Epoch, SessionId};

use crate::codec::DataTierStatus;

#[derive(Clone, Debug)]
struct Held {
    data: [SocketAddrV4; 8],
    seq: u32,
    down: u8,
}

/// The pushes owed to every open session.
#[derive(Clone, Debug, Default)]
pub struct StatusPush {
    down: BTreeSet<SocketAddrV4>,
    held: BTreeMap<(SessionId, Epoch), Held>,
}

/// Bit i set when `data[i]` is down. An unused all-zero entry is never down.
fn mask(data: &[SocketAddrV4; 8], down: &BTreeSet<SocketAddrV4>) -> u8 {
    data.iter()
        .enumerate()
        .filter(|(_, a)| !a.ip().is_unspecified() && down.contains(a))
        .fold(0u8, |m, (i, _)| m | 1 << i)
}

impl StatusPush {
    pub fn new() -> Self {
        Self::default()
    }

    /// The session got a `KeyBundle` for `epoch` with this `data` list: its `seq` 1 snapshot.
    /// A second bundle for the same epoch restarts the count, as the client holds a new bundle.
    pub fn bundle(
        &mut self,
        session: SessionId,
        epoch: Epoch,
        data: [SocketAddrV4; 8],
    ) -> DataTierStatus {
        let down = mask(&data, &self.down);
        self.held
            .insert((session, epoch), Held { data, seq: 1, down });
        DataTierStatus {
            epoch,
            seq: 1,
            down,
        }
    }

    /// The data boxes now down. Returns one status per session and epoch whose mask changed.
    pub fn set_down(&mut self, down: BTreeSet<SocketAddrV4>) -> Vec<(SessionId, DataTierStatus)> {
        self.down = down;
        let mut out = Vec::new();
        for (&(session, epoch), h) in &mut self.held {
            let m = mask(&h.data, &self.down);
            if m != h.down {
                h.seq = h.seq.saturating_add(1);
                h.down = m;
                out.push((
                    session,
                    DataTierStatus {
                        epoch,
                        seq: h.seq,
                        down: m,
                    },
                ));
            }
        }
        out
    }

    /// Forgets every session's state for `epoch` (it ended).
    pub fn retire(&mut self, epoch: Epoch) {
        self.held.retain(|&(_, e), _| e != epoch);
    }

    /// Forgets a closed session.
    pub fn close(&mut self, session: SessionId) {
        self.held.retain(|&(s, _), _| s != session);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;

    fn a(last: u8) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, last), 7000)
    }

    /// Positions are per session, `seq` is per session and epoch, unchanged masks send nothing,
    /// and a box down across a boundary is in the next epoch's snapshot.
    #[test]
    fn pushes_follow_each_sessions_list_and_count_per_epoch() {
        let (s1, s2) = (SessionId(1), SessionId(2));
        let (e, e1) = (Epoch(1000), Epoch(1001));
        let unused = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        let l1 = [a(1), a(2), a(3), unused, unused, unused, unused, unused];
        let l2 = [a(3), a(1), a(2), unused, unused, unused, unused, unused];
        let mut p = StatusPush::new();
        assert_eq!(p.bundle(s1, e, l1).seq, 1);
        assert_eq!(p.bundle(s1, e, l1).down, 0);
        p.bundle(s2, e, l2);

        // a(1) down: bit 0 for s1, bit 1 for s2.
        let got = p.set_down(BTreeSet::from([a(1)]));
        let want = vec![
            (
                s1,
                DataTierStatus {
                    epoch: e,
                    seq: 2,
                    down: 0b01,
                },
            ),
            (
                s2,
                DataTierStatus {
                    epoch: e,
                    seq: 2,
                    down: 0b10,
                },
            ),
        ];
        assert_eq!(got, want);
        // The same set again changes no mask: nothing is sent.
        assert!(p.set_down(BTreeSet::from([a(1)])).is_empty());
        // An address in no list changes nothing either.
        assert!(p.set_down(BTreeSet::from([a(1), a(9)])).is_empty());

        // The next epoch's bundle, pushed before T, carries the outage as its seq 1.
        let snap = p.bundle(
            s1,
            e1,
            [a(2), a(1), unused, unused, unused, unused, unused, unused],
        );
        assert_eq!(
            snap,
            DataTierStatus {
                epoch: e1,
                seq: 1,
                down: 0b10
            }
        );
        // a(1) recovers: each held epoch gets its own next seq.
        let got = p.set_down(BTreeSet::new());
        assert_eq!(
            got,
            vec![
                (
                    s1,
                    DataTierStatus {
                        epoch: e,
                        seq: 3,
                        down: 0
                    }
                ),
                (
                    s1,
                    DataTierStatus {
                        epoch: e1,
                        seq: 2,
                        down: 0
                    }
                ),
                (
                    s2,
                    DataTierStatus {
                        epoch: e,
                        seq: 3,
                        down: 0
                    }
                ),
            ]
        );
        p.retire(e);
        p.close(s1);
        assert!(p.set_down(BTreeSet::from([a(1)])).is_empty());
    }
}
