//! End to end over 07: a live `vyrn-engine` run is framed by `vyrn_log::SeqWriter`, decoded and
//! checked by [`OrderCore`], joined by [`DataJoin`] and replayed by [`RustReplay`]. Replay must
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
    BlockInputs, DataJoin, EpochView, OrderCore, ReplayEngine, RustReplay, full_hash, output_hash,
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

/// The engine's conformance script (`vyrn-engine/tests/engine.rs`) without the two cases 07
/// cannot carry yet (spec gaps, PR body): the `MID` boundary (the 07 codec encodes no `MID`
/// Advance record) and the `SHED` packet with its resend (live, a `SHED` record has `pkt_hash` 0
/// and gives its LaneSeqs back; 07 §3.5 hashes it and keeps them). Left: a resting order, a
/// forwarded improve, a forwarded cross, a forwarded op late at the BBO (a `Shed` step), a
/// cancel and an idle poll.
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
    ]
}

fn prefix(h: &Hash) -> PktHash {
    PktHash(u64::from_le_bytes(h.0[..8].try_into().unwrap()))
}

/// The harness's live run with the RX path's real `PktHash` (the 8-byte prefix of the packet's
/// full BLAKE3, 01 §3), which the data join keys on. Returns the journal and every payload.
fn live07(script: &[Act]) -> (Journal, Store) {
    let (bbo, mut sh) = new_box();
    let mut e = engine(bbo, &mut sh);
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
/// `cuts` and after the last record.
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
            OwnedRec::Route(_) => panic!("SeqWriter frames no RouteRecord yet"),
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
        if cuts.contains(&i) || i + 1 == j.recs.len() {
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
    let (live_j, store) = live07(&script());
    let key = vyrn_crypto::ed25519::public_key(&SEED);
    let layout = Layout::new(N as u8, 1, 0).unwrap();
    let mut core = OrderCore::<N, _>::new(layout, View(key)).unwrap();
    for f in frames(&live_j, &store, cuts) {
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
    let (bbo, mut sh) = new_box();
    let e = engine(bbo, &mut sh);
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
fn the_script_reaches_cross_improve_and_shed_steps() {
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
