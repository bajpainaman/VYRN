//! `MBO` from replay equals `MBO` from the live run, byte for byte, for this crate's script
//! and for the engine's whole conformance script (`MID`, `SHED` and its resend). A live `vyrn-engine` run
//! drives a [`SinkStream`]; the same run, framed by `vyrn_log::SeqWriter`, checked by
//! `OrderCore` and replayed by `RustReplay`, drives another. Both must emit the same packets,
//! for every block split, and the packets must rebuild the expected book.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::panic
)]

#[path = "../../engine/vyrn-engine/tests/harness/mod.rs"]
mod harness;

use harness::*;
use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::{Side as BSide, Tif};
use vyrn_engine::{OwnedRec, Rec, Sink};
use vyrn_lane::{RespPkt, Rx, RxIn};
use vyrn_log::{Ident, LaneBase, Layout, SeqWriter, TenureStart};
use vyrn_md::{MboSubscriber, Packet, Record, SinkError, SinkStream};
use vyrn_replica::{
    BlockInputs, DataJoin, EpochView, OrderCore, ReplayEngine, ReplayError, RustReplay, full_hash,
};
use vyrn_types::{
    BookId, Epoch, Handle, Hash, Height, LaneId, LaneSeq, MAX_REQ_PAYLOAD, Nanos, PacketFlags,
    PktHash, PubKey, Qty, StepFlags, StepId, StepKind,
};
use vyrn_wire::{Msg, ReqHeader, encode_request};

const SEED: [u8; 32] = [0x33; 32];

/// A `SinkStream` that gets a `CtlTimerTick` right after every step whose id is a multiple of
/// [`TICK_EVERY`], on the live and the replay side alike.
struct Md(SinkStream<Vec<Vec<u8>>>);

const TICK_EVERY: u64 = 3;

fn md() -> Md {
    Md(SinkStream::new(BOOK, Epoch(0), N, Vec::new()))
}

impl Md {
    fn finish(self) -> Result<Vec<Vec<u8>>, SinkError> {
        self.0.finish()
    }
}

impl Sink for Md {
    fn record(&mut self, r: &Rec<'_>) {
        self.0.record(r);
        if let Rec::Step(e, _) = r
            && e.step.0 % TICK_EVERY == 0
        {
            self.0.timer_tick();
        }
    }
    fn lane_resp(&mut self, l: LaneId, p: &RespPkt) {
        self.0.lane_resp(l, p);
    }
    fn tx(&mut self, h: &vyrn_bbo::TxEntry, recs: &[vyrn_bbo::Record]) {
        self.0.tx(h, recs);
    }
}

#[derive(Clone)]
struct View(PubKey);

impl EpochView for View {
    fn epoch(&self) -> Epoch {
        Epoch(0)
    }
    fn book(&self) -> BookId {
        BOOK
    }
    fn seq_key(&self, sender: u8) -> Option<PubKey> {
        (sender == 0).then_some(self.0)
    }
    fn fenced(&self, _: Height) -> bool {
        false
    }
}

/// `vyrn-replica`'s replay script (no `MID` boundary, no `SHED` resend: replay skips both
/// today), then a second session's improve pair, a cross that sweeps three makers over a run
/// of `CONT` steps, a rejected reduce, two reduces of one order in one packet, a reduce that
/// removes what is left.
fn script() -> Vec<Act> {
    use BSide::{Buy, Sell};
    use Tif::{Day, Ioc};
    let p = |l, a, rx_ts, now, msgs| Act::Pkt {
        l,
        a,
        rx_ts,
        now,
        msgs,
    };
    let reduce = |slot, by, tag| Msg::Reduce {
        handle: Handle::new(slot, 1).unwrap(),
        by: Qty(by),
        client_tag: tag,
    };
    vec![
        p(0, 1, 1_000, 1_000, vec![new(Sell, Day, 105, 5, 11)]),
        Act::Run,
        p(1, 1, 2_000, 2_000, vec![new(Buy, Day, 105, 2, 1)]),
        Act::Run,
        p(
            0,
            2,
            3_000,
            3_000,
            vec![new(Sell, Day, 110, 1, 2), new(Sell, Day, 111, 1, 3)],
        ),
        Act::Run,
        p(2, 1, 5_000, 5_000, vec![new(Buy, Ioc, 105, 1, 7)]),
        Act::Step(Some(5_000 + u64::from(FWD_DL) + 1)),
        Act::Run,
        p(
            0,
            1,
            30_000,
            30_000,
            vec![cancel(Handle::new(1, 1).unwrap(), 12)],
        ),
        Act::Poll,
        Act::Run,
        p(
            1,
            2,
            31_000,
            31_000,
            vec![new(Sell, Day, 105, 3, 20), new(Buy, Day, 100, 4, 21)],
        ),
        Act::Run,
        p(2, 3, 32_000, 32_000, vec![new(Buy, Day, 111, 5, 30)]),
        Act::Run,
        p(1, 2, 33_000, 33_000, vec![reduce(1, 1, 40)]),
        Act::Run,
        p(
            1,
            2,
            34_000,
            34_000,
            vec![reduce(3, 1, 41), reduce(3, 1, 43)],
        ),
        Act::Run,
        p(1, 2, 35_000, 35_000, vec![reduce(3, 9, 42)]),
        Act::Run,
    ]
}

/// [`script`], then a heartbeat-only packet and a join behind a heartbeat (`PacketRecord.count`
/// counts only LaneSeq-taking messages since #112, so 07 carries both).
fn script_hb() -> Vec<Act> {
    let pkt = |rx_ts, msgs| Act::Pkt {
        l: 0,
        a: 3,
        rx_ts,
        now: rx_ts,
        msgs,
    };
    let mut s = script();
    s.extend([
        pkt(36_000, vec![Msg::Heartbeat]),
        pkt(
            36_100,
            vec![Msg::Heartbeat, new(BSide::Sell, Tif::Day, 120, 1, 50)],
        ),
        Act::Run,
    ]);
    s
}

fn prefix(h: &Hash) -> PktHash {
    PktHash(u64::from_le_bytes(h.0[..8].try_into().unwrap()))
}

/// Forwards every output to the journal and to the market data adapter.
struct Both<'a>(&'a mut Journal, &'a mut Md);

impl Sink for Both<'_> {
    fn record(&mut self, r: &Rec<'_>) {
        self.0.record(r);
        self.1.record(r);
    }
    fn lane_resp(&mut self, l: LaneId, p: &RespPkt) {
        self.0.lane_resp(l, p);
        self.1.lane_resp(l, p);
    }
    fn tx(&mut self, h: &vyrn_bbo::TxEntry, recs: &[vyrn_bbo::Record]) {
        self.0.tx(h, recs);
        self.1.tx(h, recs);
    }
}

/// The live run with real `PktHash`es: the journal, every payload, and the live `MBO` packets.
fn live(script: &[Act]) -> (Journal, Store, Result<Vec<Vec<u8>>, SinkError>) {
    let (bbo, mut sh) = new_box();
    let mut e = engine(bbo, &mut sh);
    let mut j = Journal::default();
    let mut m = md();
    let mut store = Store::default();
    let mut pkt = [[0u32; NA]; N];
    for act in script {
        let mut s = Both(&mut j, &mut m);
        match act {
            Act::Pkt {
                l,
                a,
                rx_ts,
                now,
                msgs,
            } => {
                let ai = *a as usize;
                pkt[*l][ai] += 1;
                let hdr = ReqHeader::new(sid(*l, *a), pkt[*l][ai], Epoch(0).low16(), BOOK, false);
                let mut buf = [0u8; MAX_REQ_PAYLOAD];
                let n = encode_request(&mut buf, hdr, msgs, &kseq(*l, *a), None).unwrap();
                let bytes = buf[..n].to_vec();
                s.1.0.payload(&bytes);
                let rx = RxIn {
                    bytes: &bytes,
                    rx_ts: Nanos(*rx_ts),
                    pkt_hash: prefix(&full_hash(&bytes)),
                };
                let r = e.ingest(*l, rx, &FixedClock(*now), &mut s).unwrap();
                let seq = pkt[*l][ai];
                if r == Rx::Shed {
                    pkt[*l][ai] -= 1; // the client resends this pkt_seq (05 §6.8)
                }
                store
                    .0
                    .push(((LaneId(*l as u8), sid(*l, *a), seq, *rx_ts), bytes));
            }
            Act::Step(now) => {
                match now {
                    Some(t) => e.step(&FixedClock(*t), &mut s).unwrap(),
                    None => e.step(&NeverLate, &mut s).unwrap(),
                };
            }
            Act::Poll => {
                e.poll_lanes(&mut s).unwrap();
            }
            Act::Run => assert!(e.run(&NeverLate, &mut s, 64).unwrap(), "no quiescence"),
        }
    }
    (j, store, m.finish())
}

fn tenure() -> TenureStart {
    TenureStart {
        epoch: Epoch(0),
        tenure: 0,
        sender: 0,
        first_step: StepId(1),
        first_height: Height(0),
        prev_header_hash: Hash([0; 32]),
        lanes: vec![
            LaneBase {
                next_lane_seq: LaneSeq(1),
                rx_ts: Nanos(0),
                fills_applied: StepId(0),
            };
            N
        ],
        prev_cut: vec![LaneSeq(0); N],
    }
}

/// The journal framed by `SeqWriter`, a block closing after each record index in `cuts`.
fn frames(j: &Journal, store: &Store, cuts: &[usize]) -> Vec<Vec<u8>> {
    let ident = Ident {
        book: BOOK,
        epoch: Epoch(0),
        tenure: 0,
        sender: 0,
    };
    let layout = Layout::new(N as u8, 1, 0).unwrap();
    let mut w = SeqWriter::new(layout, ident, tenure(), SEED, 9000).unwrap();
    let mut out = Vec::new();
    let mut cut = vec![LaneSeq(0); N];
    let mut pending = false;
    for (i, r) in j.recs.iter().enumerate() {
        match r {
            OwnedRec::Packet(p) => {
                let full = (p.flags & PacketFlags::ADVANCE == 0).then(|| {
                    let k = (p.lane, p.session, p.pkt_seq, p.rx_ts.0);
                    let (_, b) = store.0.iter().find(|(x, _)| *x == k).unwrap();
                    full_hash(b)
                });
                out.extend(w.packet(*p, full).unwrap());
            }
            OwnedRec::Route(t) => out.extend(w.route(*t).unwrap()),
            // No pooled session in this script, so no `AcctTake` (05 §6.9).
            OwnedRec::Take(_) => unreachable!("no pooled session"),
            OwnedRec::Step(e, d) => {
                for x in &d[..usize::from(e.n_delta)] {
                    cut[usize::from(x.lane.0)] = x.seq;
                }
                let kind = StepKind::from_code(e.kind).unwrap();
                let mut payload = Vec::new();
                if kind == StepKind::Rescan {
                    payload.extend_from_slice(&e.band_lo.0.to_le_bytes());
                    payload.extend_from_slice(&e.band_hi.0.to_le_bytes());
                }
                let src = (e.src_lane_seq.0 != 0).then_some((e.src_lane, e.src_lane_seq));
                let flags = if src.is_some() && e.flags & vyrn_bbo::STEP_CROSS != 0 {
                    StepFlags::CROSS
                } else {
                    0
                };
                out.extend(w.step(e.step, kind, src, flags, payload, &cut).unwrap());
            }
        }
        // A packet's routes and `MID` records stay in its block (07 §3.6, §7.1), as vyrn-seq
        // frames them: a cut right after a packet moves past them.
        let route_next = matches!(j.recs.get(i + 1), Some(OwnedRec::Route(_)))
            || matches!(j.recs.get(i + 1),
                Some(OwnedRec::Packet(p)) if p.flags & PacketFlags::MID != 0);
        pending |= cuts.contains(&i);
        if (pending && !route_next) || i + 1 == j.recs.len() {
            pending = false;
            out.extend(w.close_block().unwrap().0);
        }
    }
    out
}

fn blocks(j: &Journal, store: &Store, cuts: &[usize]) -> Vec<BlockInputs<N>> {
    let key = vyrn_crypto::ed25519::public_key(&SEED);
    let layout = Layout::new(N as u8, 1, 0).unwrap();
    let mut core = OrderCore::<N, _>::new(layout, View(key)).unwrap();
    for f in frames(j, store, cuts) {
        core.on_frame(&f, 0).unwrap();
    }
    let blocks: Vec<_> = std::iter::from_fn(|| core.take_ready()).collect();
    assert_eq!(blocks.len(), cuts.len() + 1);
    blocks
}

/// `RustReplay` over `blocks` with a `SinkStream` as its sink: the replayed `MBO` packets, or
/// replay's own error.
fn replay_md(
    live_j: &Journal,
    store: &Store,
    blocks: &[BlockInputs<N>],
) -> Result<Vec<Vec<u8>>, ReplayError> {
    let mut data = DataJoin::default();
    for ((_, s, q, _), b) in &store.0 {
        data.put(*s, *q, b.clone());
    }
    let (bbo, mut sh) = new_box();
    let e = engine(bbo, &mut sh);
    let mut rep = RustReplay::new(e, data, RespLog::of(live_j), md());
    for b in blocks {
        rep.payloads_mut().check(b).unwrap();
        let (p, m) = rep.payloads_and_sink();
        m.0.prepare(b, p);
        rep.replay_block(b)?;
        rep.release(b.header.height);
    }
    rep.finish()?;
    Ok(rep.into_sink().finish().unwrap())
}

fn records(pkts: &[Vec<u8>]) -> Vec<Record> {
    pkts.iter()
        .flat_map(|b| Packet::decode(b).unwrap().records)
        .collect()
}

#[test]
fn replay_md_equals_live_md_byte_for_byte() {
    let (j, store, live_md) = live(&script_hb());
    let live_md = live_md.unwrap();
    let rep_md = replay_md(&j, &store, &blocks(&j, &store, &[])).unwrap();
    assert_eq!(rep_md, live_md);
}

#[test]
fn every_block_split_gives_the_same_md() {
    let (j, store, live_md) = live(&script_hb());
    let live_md = live_md.unwrap();
    for at in 0..j.recs.len() - 1 {
        let rep_md = replay_md(&j, &store, &blocks(&j, &store, &[at]))
            .unwrap_or_else(|e| panic!("split after record {at}: {e}"));
        assert_eq!(rep_md, live_md, "split after record {at}");
    }
}

/// The packets carry every book-level kind, and a subscriber that follows 10 §7.4 rebuilds
/// the book the script leaves, worked out by hand: lane 0's sell 105 (5, then 2 traded, then
/// canceled), lane 0's sells at 110 and 111 (each traded out), lane 1's sell 105 (traded out)
/// and buy 100 (4, reduced to 3 and 2 in one interval, then removed) all end, and lane 2's buy
/// 111 of 5 trades 3 + 1 + 1 over three steps, so it leaves no residual. Only lane 0's sell 120
/// of 1, behind a heartbeat, rests. Quiet lane channel 3 heartbeats before the epoch ends.
#[test]
fn the_md_rebuilds_the_book() {
    let (_, _, md) = live(&script_hb());
    let md = md.unwrap();
    let recs = records(&md);
    let has = |f: fn(&Record) -> bool| recs.iter().any(f);
    assert!(
        has(|r| matches!(r, Record::Add { via_bbo: false, .. })),
        "lane add"
    );
    assert!(
        has(|r| matches!(r, Record::Add { via_bbo: true, .. })),
        "step add"
    );
    assert!(has(|r| matches!(r, Record::Delete { .. })), "delete");
    let reduces: Vec<_> = recs
        .iter()
        .filter_map(|r| match r {
            Record::Reduce { qty, .. } => Some(qty.0),
            _ => None,
        })
        .collect();
    assert_eq!(reduces, vec![3, 2], "the second reduce sees the first");
    let execs: Vec<_> = recs
        .iter()
        .filter_map(|r| match r {
            Record::Exec { tick, qty, .. } => Some((tick.0, qty.0)),
            _ => None,
        })
        .collect();
    assert_eq!(execs, vec![(105, 2), (105, 3), (110, 1), (111, 1)]);
    let mut sub = MboSubscriber::new(BOOK, Epoch(0));
    for p in &md {
        sub.on_packet(p).unwrap();
    }
    sub.finish().unwrap();
    let rest: Vec<_> = sub
        .book()
        .orders()
        .iter()
        .map(|(o, x)| (*o, x.side, x.tick.0, x.qty.0))
        .collect();
    assert_eq!(rest.len(), 1, "{rest:?}");
    let (o, side, tick, qty) = rest[0];
    assert_eq!((o >> 24, side, tick, qty), (0, vyrn_md::Side::Sell, 120, 1));
    let quiet = md[..md.len() - 5]
        .iter()
        .map(|b| Packet::decode(b).unwrap().header);
    assert!(
        quiet.filter(|h| h.channel.index == 3).any(|h| h.count == 0),
        "a heartbeat on lane channel 3 before the epoch end"
    );
}

/// The engine's conformance script whole, as `vyrn-replica`'s replay test runs it since #106:
/// a forwarded improve whose step runs before lane 0's next packet (a `MID` Advance record), a
/// packet shed at the lane and its resend (its LaneSeqs kept, 07 §3.5), a `Shed` step, a cancel
/// and an idle poll.
/// With `twice`, the shed packet is shed a second time before any cut, then accepted.
fn engine_script_with(twice: bool) -> Vec<Act> {
    use BSide::{Buy, Sell};
    use Tif::{Day, Ioc};
    let p = |l, a, rx_ts, now, msgs| Act::Pkt {
        l,
        a,
        rx_ts,
        now,
        msgs,
    };
    vec![
        p(0, 1, 1_000, 1_000, vec![new(Sell, Day, 105, 5, 11)]),
        Act::Run,
        p(1, 1, 2_000, 2_000, vec![new(Buy, Day, 105, 2, 1)]),
        Act::Step(None),
        p(
            0,
            2,
            3_000,
            3_000,
            vec![new(Sell, Day, 110, 1, 2), new(Sell, Day, 111, 1, 3)],
        ),
        Act::Run,
        p(2, 1, 5_000, 5_000, vec![new(Buy, Ioc, 105, 1, 7)]),
        Act::Step(Some(5_000 + u64::from(FWD_DL) + 1)),
        Act::Run,
        // 05 §6.8: one New, age 462 at dequeue is late (path 519 + 462 > 980); then its resend.
        p(0, 3, 10_000, 10_462, vec![new(Sell, Day, 300, 1, 9)]),
        p(0, 3, 15_000, 15_462, vec![new(Sell, Day, 300, 1, 9)]),
        p(0, 3, 20_000, 20_461, vec![new(Sell, Day, 300, 1, 9)]),
        Act::Run,
        p(
            0,
            1,
            30_000,
            30_000,
            vec![cancel(Handle::new(1, 1).unwrap(), 12)],
        ),
        Act::Poll,
        Act::Run,
    ]
    .into_iter()
    .enumerate()
    .filter(|&(i, _)| twice || i != 10)
    .map(|(_, a)| a)
    .collect()
}

#[test]
fn mid_and_shed_resend_replay_to_the_live_md() {
    for twice in [false, true] {
        check_engine_script(twice);
    }
}

fn check_engine_script(twice: bool) {
    let (j, store, live_md) = live(&engine_script_with(twice));
    let flags: Vec<u8> = j
        .recs
        .iter()
        .filter_map(|r| match r {
            OwnedRec::Packet(p) => Some(p.flags),
            _ => None,
        })
        .collect();
    assert!(
        flags.iter().any(|f| f & PacketFlags::MID != 0),
        "a MID record"
    );
    let sheds = flags.iter().filter(|f| **f == PacketFlags::SHED).count();
    assert_eq!(sheds, 1 + usize::from(twice), "shed packets");
    let live_md = live_md.unwrap();
    // The resend rests: lane 0's sell 300 of 1, the shed copy never does.
    let adds = records(&live_md)
        .iter()
        .filter(|r| matches!(r, Record::Add { tick, .. } if tick.0 == 300))
        .count();
    assert_eq!(adds, 1);
    for at in std::iter::once(None).chain((0..j.recs.len() - 1).map(Some)) {
        let cuts: Vec<usize> = at.into_iter().collect();
        let rep_md = replay_md(&j, &store, &blocks(&j, &store, &cuts))
            .unwrap_or_else(|e| panic!("split {at:?}: {e}"));
        assert_eq!(rep_md, live_md, "split {at:?}");
    }
}
