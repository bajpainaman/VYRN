//! One step's outputs, built in preallocated buffers before anything is published (05 §8.2).

use vyrn_cut::{Floor, Snapshot};
use vyrn_types::{LaneId, SessionId, StepId, Tick};

use crate::MAX_LANES;
use crate::codec::{
    CutDelta, FillEvent, MAX_RECORDS, ROLE_DEPS, ROLE_MAKER, ROLE_TAKER, Record, StepEntry, TxEntry,
};
use crate::cut::Cut;

/// Fill events per step: ≤ 9 dependencies, ≤ 8 maker fills or kills and their taker records,
/// or one `Phase`, `Band` or `Uncross` event per lane plus a chunk's fills.
pub const MAX_EVENTS: usize = 192;
/// `TxEntry`s per step: deps, source, and one per maker session.
pub const MAX_TX: usize = 12;

/// One response packet for the fill TX core.
#[derive(Clone, Copy, Debug)]
pub struct TxOut {
    pub head: TxEntry,
    recs: [Record; MAX_RECORDS],
    /// Dependency index of each record (deps packet only): records stay in index order (05 §8.9).
    grp: [u8; MAX_RECORDS],
}

impl TxOut {
    fn new(head: TxEntry) -> Self {
        Self {
            head,
            recs: [Record::default(); MAX_RECORDS],
            grp: [0; MAX_RECORDS],
        }
    }
    /// The records, `head.n_rec` of them, in packet order.
    pub fn records(&self) -> &[Record] {
        self.recs.get(..usize::from(self.head.n_rec)).unwrap_or(&[])
    }
    /// Appends `r` after every record of group ≤ `g` (a plain append when groups are unused).
    fn push(&mut self, g: u8, r: Record) -> bool {
        let n = usize::from(self.head.n_rec);
        if n >= MAX_RECORDS {
            return false;
        }
        let at = self
            .grp
            .get(..n)
            .and_then(|gs| gs.iter().position(|x| *x > g))
            .unwrap_or(n);
        let end = n.saturating_add(1);
        if let (Some(rs), Some(gs)) = (self.recs.get_mut(at..end), self.grp.get_mut(at..end)) {
            rs.rotate_right(1);
            gs.rotate_right(1);
            if let (Some(r0), Some(g0)) = (rs.first_mut(), gs.first_mut()) {
                *r0 = r;
                *g0 = g;
            }
        }
        self.head.n_rec = self.head.n_rec.saturating_add(1);
        true
    }
}

/// Everything step `s` publishes.
#[derive(Clone, Debug)]
pub struct StepOut {
    pub entry: StepEntry,
    /// `C_s`.
    pub cut: Cut,
    deltas: [CutDelta; MAX_LANES],
    events: [(LaneId, FillEvent); MAX_EVENTS],
    n_events: usize,
    tx: [TxOut; MAX_TX],
    n_tx: usize,
    /// The snapshot to publish (always: `done_step` advances every step).
    pub snapshot: Snapshot,
    /// The `BboFloor` to publish after the snapshot.
    pub floor: Floor,
    /// Buffer overflow: an engine fault (05 §14.3); the outputs are incomplete.
    pub overflow: bool,
    pub(crate) ordinal: u32,
    pub(crate) deps_head: Option<TxEntry>,
    pub(crate) last_trade: Option<Tick>,
}

impl Default for StepOut {
    fn default() -> Self {
        Self {
            entry: StepEntry::default(),
            cut: [Default::default(); MAX_LANES],
            deltas: [CutDelta::default(); MAX_LANES],
            events: [(LaneId(0), FillEvent::default()); MAX_EVENTS],
            n_events: 0,
            tx: [TxOut::new(TxEntry::default()); MAX_TX],
            n_tx: 0,
            snapshot: Snapshot::default(),
            floor: Floor::default(),
            overflow: false,
            ordinal: 0,
            deps_head: None,
            last_trade: None,
        }
    }
}

impl StepOut {
    pub(crate) fn reset(&mut self, step: StepId) {
        self.entry = StepEntry {
            step,
            ..StepEntry::default()
        };
        self.n_events = 0;
        self.n_tx = 0;
        self.overflow = false;
        self.ordinal = 0;
        self.deps_head = None;
        self.last_trade = None;
    }

    /// Every fill event of the step, in emission order, with its lane.
    pub fn events(&self) -> &[(LaneId, FillEvent)] {
        self.events.get(..self.n_events).unwrap_or(&[])
    }

    /// Every `TxEntry` of the step, in push order (deps, source, makers).
    pub fn tx(&self) -> &[TxOut] {
        self.tx.get(..self.n_tx).unwrap_or(&[])
    }

    /// The changed cut entries, in lane order.
    pub fn deltas(&self) -> &[CutDelta] {
        self.deltas
            .get(..usize::from(self.entry.n_delta))
            .unwrap_or(&[])
    }

    pub(crate) fn set_deltas(&mut self, prev: &Cut, cut: &Cut, n_lanes: usize) {
        let mut n = 0usize;
        for (l, (p, c)) in prev.iter().zip(cut).enumerate().take(n_lanes) {
            if p != c
                && let Some(d) = self.deltas.get_mut(n)
            {
                *d = CutDelta {
                    lane: LaneId(u8::try_from(l).unwrap_or(u8::MAX)),
                    seq: *c,
                };
                n = n.saturating_add(1);
            }
        }
        self.entry.n_delta = u8::try_from(n).unwrap_or(u8::MAX);
        self.cut = *cut;
    }

    pub(crate) fn event(&mut self, lane: LaneId, mut ev: FillEvent) {
        ev.step = self.entry.step;
        match self.events.get_mut(self.n_events) {
            Some(slot) => {
                *slot = (lane, ev);
                self.n_events = self.n_events.saturating_add(1);
                if let Some(bit) = 1u64.checked_shl(u32::from(lane.0)) {
                    self.entry.fill_lanes |= bit;
                }
            }
            None => self.overflow = true,
        }
    }

    /// Next ordinal, then +1.
    pub(crate) fn next_ordinal(&mut self) -> u32 {
        let o = self.ordinal;
        self.ordinal = o.saturating_add(1);
        o
    }

    /// The open packet for `(session, role)`, opened with `head` if absent.
    fn packet(&mut self, head: TxEntry) -> Option<&mut TxOut> {
        let found = self.tx.get(..self.n_tx).and_then(|t| {
            t.iter()
                .position(|p| p.head.session == head.session && p.head.role == head.role)
        });
        let ix = match found {
            Some(i) => i,
            None => {
                let i = self.n_tx;
                *self.tx.get_mut(i)? = TxOut::new(head);
                self.n_tx = i.saturating_add(1);
                self.entry.n_tx = u8::try_from(self.n_tx).unwrap_or(u8::MAX);
                i
            }
        };
        self.tx.get_mut(ix)
    }

    /// Opens the packet without a record, fixing the deps-before-source push order.
    pub(crate) fn open(&mut self, head: TxEntry) {
        if self.packet(head).is_none() {
            self.overflow = true;
        }
    }

    /// Removes packets that got no record (an STP-only step leaves the source packet empty), so
    /// `entry.n_tx` counts exactly the `TxEntry`s published.
    pub(crate) fn drop_empty_tx(&mut self) {
        let mut k = 0usize;
        for i in 0..self.n_tx {
            if let Some(p) = self.tx.get(i).copied()
                && p.head.n_rec > 0
            {
                if let Some(d) = self.tx.get_mut(k) {
                    *d = p;
                }
                k = k.saturating_add(1);
            }
        }
        self.n_tx = k;
        self.entry.n_tx = u8::try_from(k).unwrap_or(u8::MAX);
    }

    /// The packet `head` names can take one more record (or is not open yet).
    pub(crate) fn has_room(&self, head: TxEntry) -> bool {
        self.tx()
            .iter()
            .find(|p| p.head.session == head.session && p.head.role == head.role)
            .is_none_or(|p| usize::from(p.head.n_rec) < MAX_RECORDS)
    }

    /// Appends `r` to the packet `head` names; `g` orders records of the deps packet.
    pub(crate) fn record(&mut self, head: TxEntry, g: u8, r: Record) {
        let ok = self.packet(head).is_some_and(|p| p.push(g, r));
        if !ok {
            self.overflow = true;
        }
    }

    pub(crate) fn maker_head(step: StepId, lane: LaneId, session: SessionId) -> TxEntry {
        TxEntry {
            step,
            session,
            resp_seq: 0,
            pkt_seq: 0,
            lane,
            n_rec: 0,
            role: ROLE_MAKER,
        }
    }
}

pub(crate) const fn role_head(
    step: StepId,
    lane: LaneId,
    session: SessionId,
    resp_seq: u32,
    pkt_seq: u32,
    deps: bool,
) -> TxEntry {
    TxEntry {
        step,
        session,
        resp_seq,
        pkt_seq,
        lane,
        n_rec: 0,
        role: if deps { ROLE_DEPS } else { ROLE_TAKER },
    }
}
