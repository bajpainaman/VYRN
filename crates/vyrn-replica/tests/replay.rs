//! End to end over 07: a live `vyrn-engine` run is framed by `vyrn_log::SeqWriter`, decoded and
//! checked by [`OrderCore`], joined by [`DataJoin`] (fed directly, or by a `vyrn-data` box over
//! the `sim` NIC through [`DataFeed`]) and replayed by [`RustReplay`]. Replay must
//! reproduce every lane's packet records, every lane response and every fill TX packet of the live
//! run byte for byte, and the output hash of both runs must agree.
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
use vyrn_bbo::{Side, Tif};
use vyrn_engine::OwnedRec;
use vyrn_lane::{Rx, RxIn};
use vyrn_log::{Ident, LaneBase, Layout, SeqWriter, TenureStart};
use vyrn_replica::rust::{encode_resp, encode_tx};
use vyrn_replica::{
    BlockInputs, DataFeed, DataJoin, EpochView, OrderCore, ReplayEngine, RustReplay, full_hash,
    output_hash,
};
use vyrn_types::{
    BookId, Epoch, Handle, Hash, Height, LaneId, LaneSeq, MAX_REQ_PAYLOAD, Nanos, PacketFlags,
    PktHash, PubKey, StepFlags, StepId, StepKind,
};
use vyrn_wire::{ReqHeader, encode_request};

const SEED: [u8; 32] = [0x33; 32];

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

/// The engine's conformance script (`vyrn-engine/tests/engine.rs`), whole: a resting order, a
/// forwarded improve whose step runs before lane 0's next packet (a `MID` Advance record, 07
/// §3.6), a forwarded cross, a forwarded op late at the BBO (a `Shed` step), a packet shed at
/// the lane and its resend (07 §3.6: hashed, not joined, its LaneSeqs kept), a packet whose
/// Heartbeat takes no LaneSeq, a cancel and an idle poll.
fn script() -> Vec<Act> {
    use Side::{Buy, Sell};
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
        p(0, 3, 20_000, 20_461, vec![new(Sell, Day, 300, 1, 9)]),
        Act::Run,
        // A Heartbeat takes no LaneSeq (05 §3.1), so the record counts only the New.
        p(
            1,
            2,
            25_000,
            25_000,
            vec![new(Buy, Day, 90, 1, 13), vyrn_wire::Msg::Heartbeat],
        ),
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
}

fn prefix(h: &Hash) -> PktHash {
    PktHash(u64::from_le_bytes(h.0[..8].try_into().unwrap()))
}

/// The harness's live run with the RX path's real `PktHash` (the 8-byte prefix of the packet's
/// full BLAKE3, 01 §3), which the data join keys on. Returns the journal and every payload.
fn live07(script: &[Act]) -> (Journal, Store) {
    live07_on(script, false)
}

/// [`live07`] on the harness box, with lanes 1 and 2 pooled when `pool` is set.
fn live07_on(script: &[Act], pool: bool) -> (Journal, Store) {
    let (_, mut sh) = new_box();
    let tok = vyrn_cut::PoolTok::new();
    let mut e = pooled_engine(&mut sh, &tok, pool);
    let mut j = Journal::default();
    let mut store = Store::default();
    let mut pkt = [[0u32; NA]; N];
    for act in script {
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
                let rx = RxIn {
                    bytes: &bytes,
                    rx_ts: Nanos(*rx_ts),
                    pkt_hash: prefix(&full_hash(&bytes)),
                };
                let r = e.ingest(*l, rx, &FixedClock(*now), &mut j).unwrap();
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
                    Some(t) => e.step(&FixedClock(*t), &mut j).unwrap(),
                    None => e.step(&NeverLate, &mut j).unwrap(),
                };
            }
            Act::Poll => {
                e.poll_lanes(&mut j).unwrap();
            }
            Act::Run => assert!(e.run(&NeverLate, &mut j, 64).unwrap(), "no quiescence"),
            Act::Cmd(c) => assert!(e.command(c), "control ring full"),
        }
    }
    (j, store)
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

/// Frames the live journal with `SeqWriter`, closing a block after each record index in
/// `cuts` (or after the routes and `MID` records that follow it) and after the last record.
/// Pooled lanes in `layout` frame their `AcctTake`s (07 §3.6).
fn frames_on(layout: Layout, j: &Journal, store: &Store, cuts: &[usize]) -> Vec<Vec<u8>> {
    let ident = Ident {
        book: BOOK,
        epoch: Epoch(0),
        tenure: 0,
        sender: 0,
    };
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
            // Right before its packet, as the pooled lane logs it (05 §6.9).
            OwnedRec::Take(t) => out.extend(w.take(*t).unwrap()),
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
                out.extend(
                    w.step(e.step, kind, src, flags, payload, &cut)
                        .unwrap_or_else(|x| panic!("{x:?} at {}", rec_line(r))),
                );
            }
        }
        // A packet's take, routes and `MID` records stay in its block (07 §3.6, §7.1, 05 §6.9),
        // as vyrn-seq frames them: a cut right after a take or a packet moves past them.
        let route_next = matches!(r, OwnedRec::Take(_))
            || matches!(j.recs.get(i + 1), Some(OwnedRec::Route(_)))
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

/// The live run's output hash, from its own journal.
fn live_hash(j: &Journal) -> Hash {
    let mut lanes = vec![Vec::new(); N];
    let mut tx = Vec::new();
    for (l, p) in &j.resp {
        encode_resp(&mut lanes[usize::from(l.0)], p);
    }
    for (h, recs) in &j.tx {
        encode_tx(&mut tx, h, recs);
    }
    output_hash(&lanes, &tx)
}

fn lane_pkts(j: &Journal, l: u8) -> Vec<vyrn_types::PacketRecord> {
    j.recs
        .iter()
        .filter_map(|r| match r {
            OwnedRec::Packet(p) if p.lane.0 == l => Some(*p),
            _ => None,
        })
        .collect()
}

/// The live run, framed and decoded by the order core into blocks (a block closes after each
/// record index in `cuts`).
fn blocks(cuts: &[usize]) -> (Journal, Store, Vec<BlockInputs<N>>) {
    blocks_of(&script(), cuts)
}

/// [`blocks`] of any script.
fn blocks_of(script: &[Act], cuts: &[usize]) -> (Journal, Store, Vec<BlockInputs<N>>) {
    blocks_on(script, cuts, false)
}

/// [`blocks_of`], with lanes 1 and 2 pooled when `pool` is set.
fn blocks_on(script: &[Act], cuts: &[usize], pool: bool) -> (Journal, Store, Vec<BlockInputs<N>>) {
    let (live_j, store) = live07_on(script, pool);
    let key = vyrn_crypto::ed25519::public_key(&SEED);
    let layout = Layout::new(N as u8, 1, if pool { POOL_MASK } else { 0 }).unwrap();
    let mut core = OrderCore::<N, _>::new(layout, View(key)).unwrap();
    for f in frames_on(layout, &live_j, &store, cuts) {
        core.on_frame(&f, 0).unwrap();
    }
    let blocks: Vec<_> = std::iter::from_fn(|| core.take_ready()).collect();
    assert_eq!(blocks.len(), cuts.len() + 1);
    (live_j, store, blocks)
}

/// Replays `blocks` on a fresh engine with the live run's response log. Returns the replay's
/// journal and each block's output hash, or the first error.
fn replay(
    live_j: &Journal,
    store: &Store,
    blocks: &[BlockInputs<N>],
) -> Result<(Journal, Vec<Hash>), vyrn_replica::ReplayError> {
    let mut data = DataJoin::default();
    for ((_, s, q, _), b) in &store.0 {
        data.put(*s, *q, b.clone());
    }
    replay_with(live_j, data, blocks)
}

/// [`replay`] on the pooled box.
fn replay_pooled(
    live_j: &Journal,
    store: &Store,
    blocks: &[BlockInputs<N>],
) -> Result<(Journal, Vec<Hash>), vyrn_replica::ReplayError> {
    let mut data = DataJoin::default();
    for ((_, s, q, _), b) in &store.0 {
        data.put(*s, *q, b.clone());
    }
    let (_, mut sh) = new_box();
    let tok = vyrn_cut::PoolTok::new();
    replay_on(live_j, data, blocks, pooled_engine(&mut sh, &tok, true))
}

/// [`replay`] over payloads already joined.
fn replay_with(
    live_j: &Journal,
    data: DataJoin,
    blocks: &[BlockInputs<N>],
) -> Result<(Journal, Vec<Hash>), vyrn_replica::ReplayError> {
    let (bbo, mut sh) = new_box();
    replay_on(live_j, data, blocks, engine(bbo, &mut sh))
}

/// [`replay_with`] on engine `e`, which must be in its initial state.
fn replay_on(
    live_j: &Journal,
    data: DataJoin,
    blocks: &[BlockInputs<N>],
    e: vyrn_engine::Engine<'_, vyrn_cut::Hw, NA>,
) -> Result<(Journal, Vec<Hash>), vyrn_replica::ReplayError> {
    let mut rep = RustReplay::new(e, data, RespLog::of(live_j), Journal::default());
    let mut hashes = Vec::new();
    for b in blocks {
        rep.payloads_mut().check(b).unwrap();
        hashes.push(rep.replay_block(b)?.output_hash);
        rep.release(b.header.height);
    }
    rep.finish()?;
    Ok((rep.into_sink(), hashes))
}

/// The whole path; returns the live journal, the replay's and each block's output hash.
fn run(cuts: &[usize]) -> (Journal, Journal, Vec<Hash>) {
    let (live_j, store, blocks) = blocks(cuts);
    let (rep, hashes) = replay(&live_j, &store, &blocks).unwrap();
    (live_j, rep, hashes)
}

fn check_same(live_j: &Journal, rep: &Journal) {
    for l in 0..N as u8 {
        assert_eq!(lane_pkts(rep, l), lane_pkts(live_j, l), "lane {l} records");
        let resp = |x: &Journal| {
            x.resp
                .iter()
                .filter(|r| r.0.0 == l)
                .copied()
                .collect::<Vec<_>>()
        };
        assert_eq!(resp(rep), resp(live_j), "lane {l} responses");
    }
    assert_eq!(rep.tx, live_j.tx, "fill TX packets");
}

#[test]
fn one_block_replays_the_live_run_byte_for_byte() {
    let (live_j, rep, hashes) = run(&[]);
    check_same(&live_j, &rep);
    assert_eq!(hashes, vec![live_hash(&live_j)]);
}

#[test]
fn the_script_reaches_every_case() {
    let (j, _) = live07(&script());
    let kinds: Vec<_> = j
        .recs
        .iter()
        .filter_map(|r| match r {
            OwnedRec::Step(e, _) => StepKind::from_code(e.kind),
            _ => None,
        })
        .collect();
    for k in [StepKind::Cross, StepKind::Improve, StepKind::Shed] {
        assert!(kinds.contains(&k), "{k:?} in {kinds:?}");
    }
    assert!(!j.tx.is_empty(), "a fill");
    // The cases 07 now carries: a `MID` Advance record, and a lane-shed packet that is hashed
    // and keeps its LaneSeqs, followed by its resend on the next ones (07 §3.5, §3.6).
    let pkts = lane_pkts(&j, 0);
    assert!(
        pkts.iter().any(|p| p.flags & PacketFlags::MID != 0),
        "{pkts:?}"
    );
    let shed = pkts
        .iter()
        .position(|p| p.flags == PacketFlags::SHED)
        .expect("a shed packet");
    let (s, r) = (pkts[shed], pkts[shed + 1]);
    assert_ne!(s.pkt_hash, PktHash(0));
    assert_eq!((r.session, r.pkt_seq), (s.session, s.pkt_seq), "its resend");
    assert_eq!(r.first_lane_seq.0, s.first_lane_seq.0 + u64::from(s.count));
    // The New + Heartbeat packet: one numbered message.
    let hb = lane_pkts(&j, 1)
        .into_iter()
        .find(|p| p.session == harness::sid(1, 2))
        .expect("the heartbeat packet");
    assert_eq!(hb.count, 1, "{hb:?}");
}

/// Band scripts for `snap_lag` (05 §6.5, 07 §7.1): lane 2 takes no boundary after its last
/// fill step, then classifies a buy at 300 against the newest snapshot, many versions after
/// the one its `fills_applied` step published. Replay must use the logged version, not that
/// step's.
///
/// `ask_kept`: no later step clears the ask at 105, so live the band binds (edge 210) and the
/// buy is `BAD_TICK`; the snapshot of lane 2's step 0 has no ask, so a replay that used it
/// would accept. Otherwise a Depletion step clears the ask first, so live accepts the buy, and a
/// replay that used lane 2's step-3 snapshot (ask 105) would reject it.
fn snap_lag_script(ask_kept: bool) -> Vec<Act> {
    use Side::{Buy, Sell};
    use Tif::Day;
    let p = |l, a, rx_ts, now, msgs| Act::Pkt {
        l,
        a,
        rx_ts,
        now,
        msgs,
    };
    if ask_kept {
        return vec![
            p(0, 1, 1_000, 1_000, vec![new(Sell, Day, 105, 1, 1)]),
            Act::Run,
            p(1, 1, 2_000, 2_000, vec![new(Buy, Day, 105, 1, 2)]),
            Act::Step(None),
            Act::Poll,
            p(2, 1, 3_000, 3_000, vec![new(Buy, Day, 300, 1, 3)]),
            Act::Run,
        ];
    }
    vec![
        p(0, 1, 1_000, 1_000, vec![new(Sell, Day, 105, 1, 1)]),
        Act::Run,
        // Lane 2's bid settles at a boundary whose snapshot has ask 105.
        p(2, 1, 2_000, 2_000, vec![new(Buy, Day, 90, 1, 2)]),
        Act::Run,
        // A buy empties the ask; the steps after it publish a snapshot with no ask.
        p(1, 1, 3_000, 3_000, vec![new(Buy, Day, 105, 1, 3)]),
        Act::Run,
        Act::Poll,
        p(2, 2, 4_000, 4_000, vec![new(Buy, Day, 300, 1, 4)]),
        Act::Run,
    ]
}

#[test]
fn replay_classifies_each_packet_against_its_logged_snapshot() {
    for ask_kept in [true, false] {
        let script = snap_lag_script(ask_kept);
        let (live_j, _) = live07(&script);
        let lane2 = |j: &Journal| {
            j.recs
                .iter()
                .filter_map(|r| match r {
                    OwnedRec::Packet(p) if p.lane.0 == 2 && p.count > 0 => Some(*p),
                    _ => None,
                })
                .next_back()
                .unwrap()
        };
        assert!(lane2(&live_j).snap_lag > 0, "{:?}", lane2(&live_j));
        let bad_tick = live_j.resp.iter().any(|(l, p)| {
            l.0 == 2
                && p.records().iter().any(|r| {
                    matches!(
                        r,
                        vyrn_bbo::Record::Reject {
                            reason: vyrn_types::RejectReason::BadTick,
                            detail: 210,
                            ..
                        }
                    )
                })
        });
        assert_eq!(bad_tick, ask_kept, "{:#?}", live_j.resp);
        for cuts in std::iter::once(vec![]).chain((0..live_j.recs.len() - 1).map(|at| vec![at])) {
            let (live_j, store, blocks) = blocks_of(&script, &cuts);
            let (rep, _) = replay(&live_j, &store, &blocks).unwrap_or_else(|e| {
                panic!("ask_kept {ask_kept}, blocks split after {cuts:?}: {e}")
            });
            check_same(&live_j, &rep);
        }
    }
}

#[test]
fn blocks_split_anywhere_replay_the_same() {
    let (j, _) = live07(&script());
    for at in 0..j.recs.len() - 1 {
        let (live_j, rep, hashes) = run(&[at]);
        check_same(&live_j, &rep);
        assert_eq!(hashes.len(), 2, "split after {at}");
    }
}

#[test]
fn a_changed_step_diverges() {
    let (live_j, store, blocks) = blocks(&[]);
    let mut bad = blocks.clone();
    let s = bad[0]
        .steps
        .iter_mut()
        .find(|m| m.rec.kind == StepKind::Cross)
        .unwrap();
    s.rec.kind = StepKind::Improve;
    let e = replay(&live_j, &store, &bad).unwrap_err();
    assert!(e.0.contains("diverged"), "{e}");
    // A step dropped from the end leaves logged responses unproduced.
    let mut short = blocks;
    short[0].steps.pop();
    assert!(replay(&live_j, &store, &short).is_err());
}

/// The data tier in the loop (03 F2 and F7): every client copy goes to a `vyrn-data` box over the
/// `sim` NIC, one `DATA` frame per packet. The replica loses frame 2, sees the gap at frame 3,
/// repairs it with a RANGE fetch, and then the block's `data_root` checks and replay matches the
/// live run, from payloads the replica received only from the data box.
#[test]
fn payloads_from_a_data_box_replay_the_live_run() {
    use core::net::{Ipv4Addr, SocketAddrV4};
    use vyrn_data::{DataNode, HomeConfig, Mode, NodeConfig};
    use vyrn_nic::frame::{Endpoint, FrameHdr, build, parse};
    use vyrn_nic::{
        BackendKind, NicBackend, NicConfig, PortConfig, PortId, RxBind, SimNic, TxClass,
    };
    use vyrn_wire::{RX_BURST, RxPkt, RxRing};

    let (live_j, store, blocks) = blocks(&[]);
    let ep = |last: u8, port: u16| Endpoint {
        mac: [2, 0, 0, 0, 0, last],
        ip: Ipv4Addr::new(10, 0, 0, last),
        port,
    };
    // The replica is destination 1 of data box 0, so a RANGE fetch's `dst` is not the box's `src`.
    let (ingest_ep, fetch_ep, replica_ep, client) =
        (ep(1, 19998), ep(1, 19997), ep(2, 20000), ep(9, 4000));
    let other_ep = ep(2, 20001);
    let ports = (0..2u8)
        .map(|i| PortConfig {
            id: PortId(i),
            ip: Ipv4Addr::new(10, 0, 0, i + 1),
        })
        .collect();
    let mut nic = SimNic::open(&NicConfig::new(BackendKind::Sim, ports)).unwrap();
    let bind = |e: Endpoint, port: u8| RxBind {
        lane: LaneId(0),
        port: PortId(port),
        ip: e.ip,
        udp_port: e.port,
    };
    let ingest = nic.rx_ring(&bind(ingest_ep, 0)).unwrap();
    let fetch = nic.rx_ring(&bind(fetch_ep, 0)).unwrap();
    let mut rx = nic.rx_ring(&bind(replica_ep, 1)).unwrap();
    let tx = nic.tx_ring(PortId(0), TxClass::OrderStream).unwrap();
    let mut keys = std::collections::BTreeMap::new();
    for a in script() {
        if let Act::Pkt { l, a, .. } = a {
            keys.insert(harness::sid(l, a), harness::kseq(l, a));
        }
    }
    let home = HomeConfig {
        mode: Mode::Base,
        books: vec![BOOK],
        keys,
        ring_slots: 64,
        index_key: [0x42; 16],
    };
    let mut node = DataNode::new(
        NodeConfig::new(home, 0, ingest_ep, vec![other_ep, replica_ep]),
        ingest,
        fetch,
        tx,
        vyrn_log::MemStore::default(),
    );
    let inject = |to: Endpoint, payload: &[u8]| {
        let mut b = [0u8; 1514];
        let n = build(
            &FrameHdr {
                src: client,
                dst: to,
            },
            payload,
            &mut b,
        )
        .unwrap();
        assert!(nic.inject(SocketAddrV4::new(to.ip, to.port), &b[..n], Nanos(0)));
    };
    let drain = |rx: &mut vyrn_nic::sim::SimRx| {
        let mut out = vec![];
        let mut burst = [RxPkt::empty(); RX_BURST];
        loop {
            let n = rx.poll(&mut burst);
            if n == 0 {
                return out;
            }
            out.extend(
                burst[..n]
                    .iter()
                    .map(|p| parse(rx.bytes(p)).unwrap().payload.to_vec()),
            );
            rx.release(n);
        }
    };
    for (_, b) in &store.0 {
        inject(ingest_ep, b);
        node.poll(Nanos(0));
        node.flush(Nanos(0));
    }
    let frames = drain(&mut rx);
    // 07 §5.2 step 3: the box dedupes by (session, pkt_seq) and drops a repeat with an equal
    // full hash. The lane-shed packet's resend is byte-identical, so it is stored once; both
    // PacketRecords share its pkt_hash; only the resend joins that payload (05 §18 Q17).
    let distinct: std::collections::BTreeSet<_> =
        store.0.iter().map(|((_, s, q, _), _)| (*s, *q)).collect();
    assert!(
        distinct.len() < store.0.len(),
        "the script resends a shed packet"
    );
    assert_eq!(
        frames.len(),
        distinct.len(),
        "one DATA frame per distinct packet"
    );
    assert!(frames.len() >= 3);

    let mut feed = DataFeed::new(BOOK, 1, 1);
    let mut join = DataJoin::default();
    let mut gaps = vec![];
    for (i, f) in frames.iter().enumerate() {
        if i == 1 {
            continue; // lost on the wire
        }
        let fed = feed.on_frame(&mut join, f, 0).unwrap();
        assert_eq!((fed.stored, fed.dropped), (1, 0));
        gaps.extend(fed.gap);
    }
    let gap = vyrn_replica::Gap {
        src: 0,
        dst: 1,
        from: 2,
        to: 2,
    };
    assert_eq!(gaps, vec![gap], "DATA 3 reveals that DATA 2 is missing");
    assert!(
        matches!(
            join.check(&blocks[0]),
            Err(vyrn_replica::DataErr::Missing { .. })
        ),
        "no vote while a payload is missing"
    );
    for q in gaps[0].fetches(256) {
        inject(fetch_ep, &q.encode());
    }
    node.poll(Nanos(0));
    for f in drain(&mut rx) {
        let fed = feed.on_frame(&mut join, &f, 0).unwrap();
        assert_eq!(
            (fed.stored, fed.gap),
            (1, None),
            "the resent frame, no new gap"
        );
    }
    join.check(&blocks[0]).unwrap();
    let (rep, hashes) = replay_with(&live_j, join, &blocks).unwrap();
    check_same(&live_j, &rep);
    assert_eq!(hashes, vec![live_hash(&live_j)]);
    // Silent for REP_DATA_SILENCE_MS after its last frame: the box is reported for DataDown.
    assert_eq!(
        feed.silent(vyrn_replica::REP_DATA_SILENCE_NS - 1).count(),
        0
    );
    assert_eq!(
        feed.silent(vyrn_replica::REP_DATA_SILENCE_NS)
            .collect::<Vec<_>>(),
        vec![0]
    );
}

/// The harness's box for the Vx client (`engine()`'s accounts and sessions), with
/// lanes 1 and 2 pooled as [`pooled_engine`] pools them when `pool` is set.
fn vx_config_on(pool: bool) -> vyrn_replica::VxConfig {
    use vyrn_replica::{VxAccount, VxConfig, VxSession};
    use vyrn_risk::consts as k;
    let mut c = VxConfig {
        n_lanes: N as u8,
        book: BOOK.0,
        epoch: 0,
        tick_min: 1,
        tick_max: TICK_MAX,
        tick_size: 1,
        band_bps: 10_000,
        slot_cap: SLOT_CAP,
        seg_cap: SLOT_CAP,
        pool: if pool { POOL_MASK } else { 0 },
        ..VxConfig::default()
    };
    let pooled = |l: usize, a: u32| pool && POOL_MASK & (1 << l) != 0 && a == 1;
    for l in 0..N {
        for a in 1..NA as u32 {
            c.accounts.push(VxAccount {
                slot: a,
                lane: l as u8,
                state: 0,
                max_open: 1000,
                max_qty: u32::MAX,
                max_notional: k::RSK_DEFAULT_MAX_NOTIONAL,
                taker_ppm: k::RSK_DEFAULT_TAKER_PPM,
                maker_ppm: k::RSK_DEFAULT_MAKER_PPM,
                auction_ppm: k::RSK_DEFAULT_AUCTION_PPM,
                msg_fee_improve: k::RSK_DEFAULT_MSG_FEE_IMPROVE,
                msg_fee_cross: k::RSK_DEFAULT_MSG_FEE_CROSS,
                base_free: 1 << 40,
                quote_free: 1 << 60,
                pool_ix: pooled(l, a).then_some(9),
            });
            c.sessions.push(VxSession {
                id: sid(l, a).0,
                acct: a,
                book: BOOK.0,
                k_seq: kseq(l, a),
                pooled: pooled(l, a).then_some(POOLED.0),
            });
        }
    }
    c
}

/// `target/vx/libvyrn_vx_client` from `vx/build.sh`, or `None` (the test then skips) unless
/// `VYRN_REQUIRE_VX` is set.
fn vx_lib() -> Option<std::path::PathBuf> {
    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    let lib = std::env::var_os("VYRN_VX_CLIENT_LIB").map_or_else(
        || {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../target/vx/libvyrn_vx_client.{ext}"))
        },
        std::path::PathBuf::from,
    );
    if lib.exists() {
        return Some(lib);
    }
    assert!(
        std::env::var_os("VYRN_REQUIRE_VX").is_none(),
        "{} is missing",
        lib.display()
    );
    eprintln!("skipped: {} is missing; run vx/build.sh", lib.display());
    None
}

/// One block of the Vx client: per-lane response bytes, TX bytes, output hash.
type VxBlock = (Vec<Vec<u8>>, Vec<u8>, Hash);

/// Replays `blocks` on the Vx client; returns each block's per-lane and TX bytes and hash.
fn vx_replay(
    store: &Store,
    blocks: &[BlockInputs<N>],
    lib: &std::path::Path,
) -> Result<Vec<VxBlock>, vyrn_replica::ReplayError> {
    vx_replay_on(store, blocks, lib, false)
}

/// [`vx_replay`] on the client configured as [`vx_config_on`]`(pool)`.
fn vx_replay_on(
    store: &Store,
    blocks: &[BlockInputs<N>],
    lib: &std::path::Path,
    pool: bool,
) -> Result<Vec<VxBlock>, vyrn_replica::ReplayError> {
    let mut data = DataJoin::default();
    for ((_, s, q, _), b) in &store.0 {
        data.put(*s, *q, b.clone());
    }
    let mut vx = vyrn_replica::VxReplay::new(lib, &vx_config_on(pool), data)?;
    let mut out = Vec::new();
    for b in blocks {
        let h = vx.replay_block(b)?.output_hash;
        out.push((vx.lane_bytes().to_vec(), vx.tx_bytes().to_vec(), h));
    }
    Ok(out)
}

/// The live run's per-lane response bytes and TX bytes, as `output_hash` covers them.
fn live_bytes(j: &Journal) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut lanes = vec![Vec::new(); N];
    let mut tx = Vec::new();
    for (l, p) in &j.resp {
        encode_resp(&mut lanes[usize::from(l.0)], p);
    }
    for (h, recs) in &j.tx {
        encode_tx(&mut tx, h, recs);
    }
    (lanes, tx)
}

/// M3 (11 §8): the Vx client and `RustReplay` produce the same bytes and output hash over the
/// whole script.
#[test]
fn the_vx_client_matches_rust_replay() {
    let Some(lib) = vx_lib() else { return };
    let (live_j, store, blocks) = blocks(&[]);
    let (_, rust_hashes) = replay(&live_j, &store, &blocks).unwrap();
    let vx = vx_replay(&store, &blocks, &lib).unwrap();
    let (lanes, tx) = live_bytes(&live_j);
    for l in 0..N {
        assert_eq!(vx[0].0[l], lanes[l], "lane {l} responses");
    }
    assert_eq!(vx[0].1, tx, "fill TX packets");
    assert!(
        !tx.is_empty() && !lanes[0].is_empty(),
        "responses and fills to compare"
    );
    assert_eq!(vec![vx[0].2], rust_hashes);
    // A changed step diverges on the client too.
    let mut bad = blocks;
    let s = bad[0]
        .steps
        .iter_mut()
        .find(|m| m.rec.kind == StepKind::Cross)
        .unwrap();
    s.rec.kind = StepKind::Improve;
    let e = vx_replay(&store, &bad, &lib).unwrap_err();
    assert!(e.0.contains("diverged"), "{e}");
}

/// Every block boundary the order core allows gives both engines the same output hashes.
#[test]
fn the_vx_client_matches_rust_replay_split_anywhere() {
    let Some(lib) = vx_lib() else { return };
    let (j, _) = live07(&script());
    for at in 0..j.recs.len() - 1 {
        let (live_j, store, blocks) = blocks(&[at]);
        let (_, rust_hashes) = replay(&live_j, &store, &blocks).unwrap();
        let vx =
            vx_replay(&store, &blocks, &lib).unwrap_or_else(|e| panic!("split after {at}: {e}"));
        let h: Vec<Hash> = vx.iter().map(|x| x.2).collect();
        assert_eq!(h, rust_hashes, "split after {at}");
    }
}

/// A script where the price band binds on a stale bound (11 §5.3 band reference): a buy
/// empties the last ask at 105, and before any later step observes the bounds a buy at 300 is
/// checked against the published ask. Rust's `Bbo::finish` keeps the conservative bound (ask
/// 105, edge 210), so that buy is a `BAD_TICK` reject on both engines.
fn band_script() -> Vec<Act> {
    use Side::{Buy, Sell};
    use Tif::Day;
    let p = |l, a, rx_ts, now, msgs| Act::Pkt {
        l,
        a,
        rx_ts,
        now,
        msgs,
    };
    vec![
        p(0, 1, 1_000, 1_000, vec![new(Sell, Day, 105, 1, 1)]),
        Act::Run,
        p(1, 1, 2_000, 2_000, vec![new(Buy, Day, 105, 1, 2)]),
        Act::Step(None),
        // The buyer applies its fill (an Advance at step 3), then sends a buy far above 105.
        Act::Poll,
        p(1, 2, 3_000, 3_000, vec![new(Buy, Day, 300, 1, 3)]),
        Act::Run,
    ]
}

#[test]
fn the_vx_client_matches_rust_replay_when_the_band_binds() {
    let (live_j, store, blocks) = blocks_of(&band_script(), &[]);
    let (rep, rust_hashes) = replay(&live_j, &store, &blocks).unwrap();
    check_same(&live_j, &rep);
    // The case is reached: a BAD_TICK reject against the stale ask.
    let bad_tick = live_j.resp.iter().any(|(_, p)| {
        p.records().iter().any(|r| {
            matches!(
                r,
                vyrn_bbo::Record::Reject {
                    reason: vyrn_types::RejectReason::BadTick,
                    ..
                }
            )
        })
    });
    assert!(bad_tick, "{:#?}", live_j.resp);
    let Some(lib) = vx_lib() else { return };
    let vx = vx_replay(&store, &blocks, &lib).unwrap();
    let (lanes, tx) = live_bytes(&live_j);
    for l in 0..N {
        assert_eq!(vx[0].0[l], lanes[l], "lane {l} responses");
    }
    assert_eq!(vx[0].1, tx, "fill TX packets");
    assert_eq!(vec![vx[0].2], rust_hashes);
    // The same at every block boundary.
    let (j, _) = live07(&band_script());
    for at in 0..j.recs.len() - 1 {
        let (live_j, store, blocks) = blocks_of(&band_script(), &[at]);
        let (_, rust_hashes) = replay(&live_j, &store, &blocks).unwrap();
        let vx =
            vx_replay(&store, &blocks, &lib).unwrap_or_else(|e| panic!("split after {at}: {e}"));
        let h: Vec<Hash> = vx.iter().map(|x| x.2).collect();
        assert_eq!(h, rust_hashes, "split after {at}");
    }
}

/// Lanes that take Advance boundaries after their last packet while steps move other lanes'
/// cuts (found by a search over small scripts). Each step's envelope must start at the
/// snapshot version each lane's ops read, which the Vx client keeps in its own lane word: a
/// client that read it from the `fills_applied` word (pbv lane word 3) narrows the envelope
/// and diverges here, while every other test still passes.
fn version_script() -> Vec<Act> {
    use Side::{Buy, Sell};
    use Tif::Day;
    let p = |l, a, t: u64, msgs| Act::Pkt {
        l,
        a,
        rx_ts: t,
        now: t,
        msgs,
    };
    vec![
        p(0, 2, 1_000, vec![new(Sell, Day, 400, 1, 1)]),
        Act::Run,
        p(1, 3, 2_000, vec![new(Sell, Day, 150, 1, 2)]),
        Act::Poll,
        p(0, 3, 3_000, vec![new(Sell, Day, 150, 1, 3)]),
        Act::Poll,
        p(1, 2, 4_000, vec![new(Buy, Day, 100, 2, 4)]),
        Act::Run,
        p(2, 2, 5_000, vec![new(Sell, Day, 105, 1, 5)]),
        Act::Step(None),
        p(2, 4, 6_000, vec![new(Sell, Day, 400, 2, 6)]),
        Act::Step(None),
        p(1, 1, 7_000, vec![new(Sell, Day, 400, 1, 7)]),
        Act::Poll,
        p(2, 1, 8_000, vec![new(Buy, Day, 400, 1, 8)]),
        Act::Run,
        p(2, 3, 9_000, vec![new(Sell, Day, 110, 1, 9)]),
        Act::Step(None),
        p(1, 1, 10_000, vec![new(Buy, Day, 300, 2, 10)]),
        Act::Step(None),
        p(2, 1, 11_000, vec![new(Sell, Day, 400, 1, 11)]),
        Act::Poll,
        Act::Run,
    ]
}

#[test]
fn the_vx_client_keeps_each_lanes_snapshot_version() {
    let (live_j, store, blocks) = blocks_of(&version_script(), &[]);
    let (rep, rust_hashes) = replay(&live_j, &store, &blocks).unwrap();
    check_same(&live_j, &rep);
    let rejects = live_j
        .resp
        .iter()
        .flat_map(|(_, p)| p.records())
        .filter(|r| {
            matches!(
                r,
                vyrn_bbo::Record::Reject {
                    reason: vyrn_types::RejectReason::BadTick,
                    ..
                }
            )
        })
        .count();
    assert_eq!(rejects, 2, "{:#?}", live_j.resp);
    let Some(lib) = vx_lib() else { return };
    let vx = vx_replay(&store, &blocks, &lib).unwrap();
    let (lanes, tx) = live_bytes(&live_j);
    for l in 0..N {
        assert_eq!(vx[0].0[l], lanes[l], "lane {l} responses");
    }
    assert_eq!(vx[0].1, tx, "fill TX packets");
    assert_eq!(vec![vx[0].2], rust_hashes);
}

/// More forwarded ops due before one step than the Vx client's forwarded queue holds
/// (`FWDQ_CAP` = 1024). Live, lane 0 fills Rust's forward ring with 1024 sells, one step lets
/// the BBO take 10 of them into its lane buffer, and 9 more sells that improve the ask follow
/// before the lane takes a boundary: 1033 forwarded ops with `fills_applied` 0, all due before
/// step 1 on replay (the harness's `SLOT_CAP` leaves the lane room for them). Rust replays it;
/// the Vx client must halt with `PBV_E_FAULT` (a v1 capacity limit, 11 §5.3) instead of
/// waiting forever on itself (Codex r4610220906).
fn fwd_overflow_script() -> Vec<Act> {
    let mut sc = Vec::new();
    let mut ts = 1_000_000u64;
    let mut tag = 1u32;
    let mut pkt = |sc: &mut Vec<Act>, a: u32, n: u32, below: bool| {
        let msgs = (0..n)
            .map(|i| {
                tag += 1;
                let tick = if below { 190 - i } else { 200 + tag % 300 };
                new(Side::Sell, Tif::Day, tick, 1, tag)
            })
            .collect();
        sc.push(Act::Pkt {
            l: 0,
            a,
            rx_ts: ts,
            now: ts,
            msgs,
        });
        ts += 1_000_000;
    };
    for i in 0..102u32 {
        pkt(&mut sc, 1 + i % 15, 10, false);
    }
    pkt(&mut sc, 1, 4, false);
    sc.push(Act::Step(None));
    pkt(&mut sc, 2, 9, true);
    for _ in 0..40 {
        sc.push(Act::Poll);
        for _ in 0..30 {
            sc.push(Act::Step(None));
        }
    }
    sc.push(Act::Run);
    sc
}

#[test]
fn the_vx_client_halts_on_a_forwarded_queue_overflow() {
    let (live_j, store, blocks) = blocks_of(&fwd_overflow_script(), &[]);
    let pending = lane_pkts(&live_j, 0)
        .iter()
        .filter(|p| p.flags == 0 && p.fills_applied.0 == 0)
        .map(|p| u64::from(p.count))
        .sum::<u64>();
    assert_eq!(pending, 1033, "all due before step 1");
    replay(&live_j, &store, &blocks).unwrap();
    let Some(lib) = vx_lib() else { return };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(vx_replay(&store, &blocks, &lib).map(|_| ()));
    });
    let r = rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the Vx client deadlocked on its forwarded queue");
    let e = r.unwrap_err();
    assert!(e.0.contains("diverged (fault)"), "{e}");
}

/// The Vx client and `RustReplay` produce the live run's bytes and the same output hash in one
/// block, and the same output hashes with the blocks split after each record index in `splits`.
fn assert_vx_matches(script: &[Act], splits: impl IntoIterator<Item = usize>) {
    let Some(lib) = vx_lib() else { return };
    let (live_j, store, blocks) = blocks_of(script, &[]);
    let (_, rust_hashes) = replay(&live_j, &store, &blocks).unwrap();
    let vx = vx_replay(&store, &blocks, &lib).unwrap();
    let (lanes, tx) = live_bytes(&live_j);
    for l in 0..N {
        assert_eq!(vx[0].0[l], lanes[l], "lane {l} responses");
    }
    assert_eq!(vx[0].1, tx, "fill TX packets");
    assert_eq!(vec![vx[0].2], rust_hashes);
    for at in splits {
        let (live_j, store, blocks) = blocks_of(script, &[at]);
        let (_, rust_hashes) = replay(&live_j, &store, &blocks).unwrap();
        let vx =
            vx_replay(&store, &blocks, &lib).unwrap_or_else(|e| panic!("split after {at}: {e}"));
        let h: Vec<Hash> = vx.iter().map(|x| x.2).collect();
        assert_eq!(h, rust_hashes, "split after {at}");
    }
}

/// `snap_lag` (05 §6.5, 07 §7.1) on the Vx client: each packet is classified against the
/// version its record names, not its `fills_applied` step's, in both band cases of
/// [`snap_lag_script`], at every block boundary.
#[test]
fn the_vx_client_classifies_each_packet_against_its_logged_snapshot() {
    for ask_kept in [true, false] {
        let script = snap_lag_script(ask_kept);
        let (j, _) = live07(&script);
        assert_vx_matches(&script, 0..j.recs.len() - 1);
    }
}

/// More snapshot versions than replay keeps (`REPLAY_SNAP_HIST` = 4096, 07 §7.1): each of 5
/// sweeps rests 500 rising bids on lane 1 (one version each) and fills them with IOC sells
/// from lane 2, while lane 0 has no work and takes no boundary. Then lane 0 sends a join
/// (`join`) or a Heartbeat. Slots are not reused, so the harness's `SLOT_CAP` (4096) is what
/// lets each lane take 2500 ops.
fn window_script(join: bool) -> Vec<Act> {
    use Side::{Buy, Sell};
    use Tif::{Day, Ioc};
    let p = |l, a, rx_ts, msgs| Act::Pkt {
        l,
        a,
        rx_ts,
        now: rx_ts,
        msgs,
    };
    let mut s = Vec::new();
    let mut t = 1_000u64;
    let mut tag = 0u32;
    for _ in 0..5 {
        for (l, a0, n) in [(1, 1, 10), (2, 1, 5)] {
            for k in 0..500u32 {
                tag += 1;
                let m = if l == 1 {
                    new(Buy, Day, 2 + k, 1, tag)
                } else {
                    new(Sell, Ioc, 1, 1, tag)
                };
                s.push(p(l, a0 + k % n, t, vec![m]));
                s.push(Act::Run);
                t += 1_000;
            }
        }
    }
    let last = if join {
        new(Buy, Day, 1, 1, tag + 1)
    } else {
        vyrn_wire::Msg::Heartbeat
    };
    s.push(p(0, 1, t, vec![last]));
    s.push(Act::Run);
    s
}

/// 05 §6.5: a lane whose lag would pass the window (`REPLAY_SNAP_HIST` − 1) first takes a
/// catch-up boundary, so every logged lag names a version replay holds; the Vx client follows
/// the catch-up Advance and the join's lag as `RustReplay` does (vyrn-engine
/// `a_lagging_lane_catches_up_before_its_lag_leaves_the_replay_window`).
#[test]
fn the_vx_client_follows_a_lagging_lanes_catch_up() {
    let script = window_script(true);
    let (j, _) = live07(&script);
    let window = u16::try_from(vyrn_engine::REPLAY_SNAP_HIST - 1).unwrap();
    assert_eq!(vyrn_engine::SNAP_LAG_WINDOW, window);
    for r in &j.recs {
        if let OwnedRec::Packet(p) = r {
            assert!(p.snap_lag <= window, "{p:?}");
        }
    }
    let l0 = lane_pkts(&j, 0);
    let k = l0.iter().position(|p| p.count > 0).unwrap();
    assert!(
        k > 0 && l0[k - 1].flags & vyrn_types::PacketFlags::ADVANCE != 0,
        "{l0:?}"
    );
    assert!(l0[k].fills_applied.0 > 0, "{:?}", l0[k]);
    // One block, then splits around lane 0's catch-up and join.
    let at = j
        .recs
        .iter()
        .position(|r| matches!(r, OwnedRec::Packet(p) if p.lane.0 == 0))
        .unwrap();
    assert_vx_matches(&script, [at - 1, at, at + 1, at + 2]);
}

/// 07 §7.1: a packet record whose version the ring no longer holds is `NoSnapshot` on
/// `RustReplay` and `PBV_E_FAULT` on the Vx client (vyrn-engine
/// `a_packet_naming_an_evicted_snapshot_is_no_snapshot`). Lane 0's Heartbeat moves to a later
/// block without its catch-up Advance, so it names version 0 + its lag, evicted after the
/// script's 5000 versions.
#[test]
fn the_vx_client_reports_an_evicted_snapshot() {
    let (live_j, store, mut blocks) = blocks_of(&window_script(false), &[]);
    let b = &mut blocks[0];
    let is_l0 = |r: &vyrn_log::LaneRec| matches!(r, vyrn_log::LaneRec::Pkt(p) if p.lane.0 == 0);
    let i = b.lanes.iter().position(is_l0).unwrap();
    let vyrn_log::LaneRec::Pkt(adv) = b.lanes[i] else {
        unreachable!()
    };
    let vyrn_log::LaneRec::Pkt(mut hb) = b.lanes[i + 1] else {
        unreachable!()
    };
    assert!(adv.flags & vyrn_types::PacketFlags::ADVANCE != 0, "{adv:?}");
    assert!(hb.lane.0 == 0 && hb.count == 0 && hb.flags == 0, "{hb:?}");
    assert!(hb.snap_lag < 4096, "{hb:?}");
    b.lanes.drain(i..i + 2);
    if i < b.split {
        b.split -= 2;
    }
    hb.fills_applied = vyrn_types::StepId(0);
    let later = BlockInputs {
        header: b.header,
        lanes: vec![vyrn_log::LaneRec::Pkt(hb)],
        split: 1,
        steps: Vec::new(),
    };
    blocks.push(later);
    // RustReplay without `payloads_mut().check`: the edited blocks no longer match their roots.
    let mut data = DataJoin::default();
    for ((_, s, q, _), b) in &store.0 {
        data.put(*s, *q, b.clone());
    }
    let (bbo, mut sh) = new_box();
    let mut rep = RustReplay::new(
        engine(bbo, &mut sh),
        data,
        RespLog::of(&live_j),
        Journal::default(),
    );
    rep.replay_block(&blocks[0]).unwrap();
    let e = rep.replay_block(&blocks[1]).unwrap_err();
    assert!(e.0.contains("NoSnapshot"), "{e}");
    let Some(lib) = vx_lib() else { return };
    let e = vx_replay(&store, &blocks, &lib).unwrap_err();
    assert!(e.0.contains("diverged (fault)"), "{e}");
}

/// Pooled sessions on lanes 1 and 2 (account 77): takes `ver` 1, 2, 3 across both pool lanes,
/// a crossing pooled IOC (`[Take, Packet, Route]`), and a dedicated lane in between.
fn pool_script() -> Vec<Act> {
    use Side::{Buy, Sell};
    use Tif::{Day, Ioc};
    let mut s = Vec::new();
    for (k, (l, a, m)) in [
        (1, 1, new(Sell, Day, 200, 2, 1)),
        (0, 1, new(Sell, Day, 201, 1, 2)),
        (2, 1, new(Sell, Day, 202, 1, 3)),
        (1, 1, new(Buy, Ioc, 200, 1, 4)),
        (2, 2, new(Sell, Day, 203, 1, 5)),
    ]
    .into_iter()
    .enumerate()
    {
        let t = 1_000 * (k as u64 + 1);
        s.push(Act::Pkt {
            l,
            a,
            rx_ts: t,
            now: t,
            msgs: vec![m],
        });
        s.push(Act::Run);
    }
    s
}

#[test]
fn pooled_takes_replay_through_framed_blocks() {
    // Follow-up 1 of #157: `AcctTake`s go through `SeqWriter`, the order core and
    // `RustReplay`, at every block split, with the live run's bytes and responses.
    let (live_j, _, _) = blocks_on(&pool_script(), &[], true);
    let takes: Vec<_> = live_j
        .recs
        .iter()
        .filter_map(|r| match r {
            OwnedRec::Take(t) => Some((t.lane.0, t.ver)),
            _ => None,
        })
        .collect();
    assert_eq!(takes, vec![(1, 1), (2, 2), (1, 3)]);
    assert!(
        live_j.recs.windows(3).any(|w| matches!(
            w,
            [OwnedRec::Take(_), OwnedRec::Packet(_), OwnedRec::Route(_)]
        )),
        "the pooled IOC logs [Take, Packet, Route]"
    );
    for cut in 0..live_j.recs.len() {
        let cuts: Vec<usize> = if cut == 0 { Vec::new() } else { vec![cut - 1] };
        let (live_j, store, blocks) = blocks_on(&pool_script(), &cuts, true);
        let (rep, hashes) = replay_pooled(&live_j, &store, &blocks)
            .unwrap_or_else(|e| panic!("split {cuts:?}: {e}"));
        check_same(&live_j, &rep);
        if cuts.is_empty() {
            assert_eq!(*hashes.last().unwrap(), live_hash(&live_j));
        }
    }
    // An unpooled engine emits no take, so replaying the pooled blocks diverges at the first.
    let (live_j, store, blocks) = blocks_on(&pool_script(), &[], true);
    assert!(replay(&live_j, &store, &blocks).is_err());
}

/// `RustReplay` on the pooled (`pool`) or plain box over `blocks`, without the data-root check
/// (the edited blocks below no longer match their headers).
fn rust_unchecked(
    live_j: &Journal,
    store: &Store,
    blocks: &[BlockInputs<N>],
    pool: bool,
) -> Result<Vec<Hash>, vyrn_replica::ReplayError> {
    let mut data = DataJoin::default();
    for ((_, s, q, _), b) in &store.0 {
        data.put(*s, *q, b.clone());
    }
    let (_, mut sh) = new_box();
    let tok = vyrn_cut::PoolTok::new();
    let mut rep = RustReplay::new(
        pooled_engine(&mut sh, &tok, pool),
        data,
        RespLog::of(live_j),
        Journal::default(),
    );
    blocks
        .iter()
        .map(|b| rep.replay_block(b).map(|o| o.output_hash))
        .collect()
}

/// vyrn-engine `replay_wire_reproduces_each_take_and_carries_it_with_its_packet` on the Vx
/// client (05 §6.9, 07 §7.1): each `AcctTake` is reproduced right before its packet record in
/// the pool's `ver` order (lane 1's ver 3 waits for lane 2's ver 2), and carries with its packet
/// across blocks. Vx and `RustReplay` give the live bytes and the same output hashes at every
/// block split, and both reject each malformed take (`PBV_E_FAULT` on the client).
#[test]
fn the_vx_client_reproduces_each_take_in_pool_order() {
    let script = pool_script();
    let (live_j, store, blocks) = blocks_on(&script, &[], true);
    let (_, rust_hashes) = replay_pooled(&live_j, &store, &blocks).unwrap();
    let Some(lib) = vx_lib() else { return };
    let vx = vx_replay_on(&store, &blocks, &lib, true).unwrap();
    let (lanes, tx) = live_bytes(&live_j);
    for l in 0..N {
        assert_eq!(vx[0].0[l], lanes[l], "lane {l} responses");
    }
    assert_eq!(vx[0].1, tx, "fill TX packets");
    assert!(!tx.is_empty(), "the pooled IOC fills");
    assert_eq!(vec![vx[0].2], rust_hashes);
    for at in 0..live_j.recs.len() - 1 {
        let (live_j, store, blocks) = blocks_on(&script, &[at], true);
        let (_, rust_hashes) = replay_pooled(&live_j, &store, &blocks).unwrap();
        let vx = vx_replay_on(&store, &blocks, &lib, true)
            .unwrap_or_else(|e| panic!("split after {at}: {e}"));
        let h: Vec<Hash> = vx.iter().map(|x| x.2).collect();
        assert_eq!(h, rust_hashes, "split after {at}");
    }

    // A first block with no steps replays only what is due at step 0; the later pooled packets
    // carry, each with its take, into a block that holds every step.
    let b = &blocks[0];
    let mut first = b.clone();
    first.steps.clear();
    first.header.last_step = StepId(0);
    let rest = BlockInputs {
        header: b.header,
        lanes: Vec::new(),
        split: 0,
        steps: b.steps.clone(),
    };
    let two = [first, rest];
    let rust = rust_unchecked(&live_j, &store, &two, true).unwrap();
    let vx = vx_replay_on(&store, &two, &lib, true).unwrap();
    assert_eq!(vx.iter().map(|x| x.2).collect::<Vec<_>>(), rust);
    assert_eq!(
        rust[1], rust_hashes[0],
        "the carried run gives the one-block hash"
    );

    // Malformed takes: both engines reject each, the client with PBV_E_FAULT where it is the
    // one that finds it, the shell where the input is misplaced or repeated.
    let take_at = |k: usize| {
        b.lanes
            .iter()
            .enumerate()
            .filter(|(_, r)| matches!(r, vyrn_log::LaneRec::Take(_)))
            .nth(k)
            .map(|(i, _)| i)
            .unwrap()
    };
    let edit = |f: &dyn Fn(&mut Vec<vyrn_log::LaneRec>)| {
        let mut x = b.clone();
        f(&mut x.lanes);
        x.split = x.lanes.len();
        vec![x]
    };
    let fault = |blocks: &[BlockInputs<N>], pool: bool, why: &str| {
        assert!(
            rust_unchecked(&live_j, &store, blocks, pool).is_err(),
            "rust: {why}"
        );
        let e = vx_replay_on(&store, blocks, &lib, pool).unwrap_err();
        assert!(e.0.contains("diverged (fault)"), "{why}: {e}");
    };
    let rejected = |blocks: &[BlockInputs<N>], why: &str| {
        assert!(
            rust_unchecked(&live_j, &store, blocks, true).is_err(),
            "rust: {why}"
        );
        let e = vx_replay_on(&store, blocks, &lib, true).unwrap_err();
        assert!(e.0.contains("AcctTake"), "{why}: {e}");
    };
    let set = |k: usize, f: &dyn Fn(&mut vyrn_types::AcctTake)| {
        edit(&|l: &mut Vec<vyrn_log::LaneRec>| {
            if let vyrn_log::LaneRec::Take(t) = &mut l[take_at(k)] {
                f(t);
            }
        })
    };
    fault(
        &set(2, &|t| t.ver += 10),
        true,
        "the last take's ver changed",
    );
    fault(
        &set(0, &|t| t.account = vyrn_types::AccountId(78)),
        true,
        "another account",
    );
    fault(
        &edit(&|l| {
            l.remove(take_at(0));
        }),
        true,
        "a dropped take",
    );
    fault(&blocks, false, "a box without the pool");
    rejected(
        &edit(&|l| {
            let t = l[take_at(0)];
            l.insert(take_at(0), t);
        }),
        "a repeated take",
    );
    rejected(
        &edit(&|l| {
            let i = take_at(0);
            if let vyrn_log::LaneRec::Take(t) = l[i] {
                l.insert(
                    i,
                    vyrn_log::LaneRec::Take(vyrn_types::AcctTake { ver: 99, ..t }),
                );
            }
        }),
        "a second take on one record",
    );
    // A take bound to an Advance record of its lane.
    let adv = b.lanes.iter().position(|r| {
        matches!(r, vyrn_log::LaneRec::Pkt(p)
            if p.lane.0 == 1 && p.flags & PacketFlags::ADVANCE != 0)
    });
    if let Some(i) = adv {
        rejected(
            &edit(&|l| {
                let t = l.remove(take_at(0));
                let j = if i > take_at(0) { i - 1 } else { i };
                l.insert(j, t);
            }),
            "a take before an Advance record",
        );
    }
}
