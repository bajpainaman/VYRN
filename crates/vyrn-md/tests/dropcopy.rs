//! Drop copy from replay equals drop copy from the live run, and both agree with the live
//! response stream. A live `vyrn-engine` run drives a `SinkStream` with a `DropCopy` tap; the
//! same run, framed by `vyrn_log::SeqWriter`, checked by `OrderCore` and replayed by
//! `RustReplay`, drives another, for every block split. Then:
//!
//! - the canonical records (every record but `DC_FINAL`) are byte-identical, live and replay;
//! - every client record of the live response stream (`Ack`, `CancelAck`, `Out`, `Fill`) has
//!   exactly one drop-copy counterpart on its account's stream, field for field, found by
//!   `(session, resp_seq)` (10 §8.3); a taker's per-level `Fill` equals the sum of its per-match
//!   `DC_FILL`s;
//! - the fees on the streams sum to the engine's own `fee_acc` (10 §5.5);
//! - every `DC_FINAL` covers only released steps, and the last `DC_EOD` hashes the stream.
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

use std::collections::BTreeMap;

use harness::*;
use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::{Bbo, Record as Resp, Side as BSide, Tif};
use vyrn_cut::Hw;
use vyrn_engine::{Engine, OwnedRec, Rec, Shared, Sink};
use vyrn_lane::{Config, Lane, PathTable, RespPkt, Rx, RxIn, SessionSpec};
use vyrn_log::{Ident, LaneBase, Layout, SeqWriter, TenureStart};
use vyrn_md::SinkStream;
use vyrn_md::dropcopy::{DcAccount, DcConfig, DcRecord, DcType, DropCopy, EOD_HASH, StreamId};
use vyrn_replica::{
    BlockInputs, DataJoin, EpochView, OrderCore, ReplayEngine, ReplayError, RustReplay, full_hash,
};
use vyrn_risk::{AcctRisk, AcctSlot, BookSpec, FeeRates, SessionBuckets};
use vyrn_types::{
    AccountId, Epoch, Handle, Hash, Height, LaneId, LaneSeq, MAX_REQ_PAYLOAD, Nanos, PacketFlags,
    PktHash, PubKey, Qty, StepFlags, StepId, StepKind, Tick,
};
use vyrn_wire::{Msg, ReqHeader, encode_request};

const SEED: [u8; 32] = [0x33; 32];
const TICK_SIZE: u64 = 10;
const MASTER: AccountId = AccountId(900);

type Recs = Vec<(StreamId, u64, DcRecord)>;
type Md = SinkStream<Vec<Vec<u8>>, DropCopy<Recs>>;

fn account(l: usize, a: u32) -> AccountId {
    AccountId(100 + 16 * l as u32 + a)
}

/// Odd sessions pay 400 ppm as takers and get a 20 ppm rebate as makers; even ones pay 300 and
/// 50. Sessions 1 and 2 of every lane are sub-accounts of [`MASTER`].
fn rates(a: u32) -> FeeRates {
    if a % 2 == 1 {
        FeeRates::new(400, -20, 100, 8, 15).unwrap()
    } else {
        FeeRates::new(300, 50, 100, 8, 15).unwrap()
    }
}

fn master(a: u32) -> Option<AccountId> {
    (a <= 2).then_some(MASTER)
}

fn dc_config() -> DcConfig {
    let mut accounts = Vec::new();
    for l in 0..N {
        for a in 1..NA as u32 {
            let r = rates(a);
            accounts.push(DcAccount {
                account: account(l, a),
                master: master(a),
                sessions: vec![sid(l, a)],
                taker_ppm: r.taker_ppm,
                maker_ppm: r.maker_ppm,
                msg_fee_improve: r.msg_fee_improve,
                msg_fee_cross: r.msg_fee_cross,
            });
        }
    }
    DcConfig {
        book: BOOK,
        tick_size: TICK_SIZE,
        accounts,
    }
}

fn md() -> Md {
    SinkStream::with_tap(
        BOOK,
        Epoch(0),
        N,
        Vec::new(),
        DropCopy::new(&dc_config(), Vec::new()),
    )
}

/// The harness box with fees: [`rates`] per session and `tick_size` [`TICK_SIZE`].
fn fee_engine(bbo: Bbo, sh: &mut Shared<Hw>) -> Engine<'_, Hw, NA> {
    let cfgs: Vec<Config> = (0..N)
        .map(|l| Config {
            lane: LaneId(l as u8),
            n_lanes: N as u8,
            epoch: Epoch(0),
            book: BOOK,
            spec: BookSpec::new(TICK_SIZE, Tick(1), Tick(TICK_MAX), 10_000).unwrap(),
            path: PathTable::spec(),
            fwd_deadline_ns: FWD_DL,
            phase: vyrn_bbo::Phase::Continuous,
            out_cap: 4096,
        })
        .collect();
    Engine::new(&Hw, sh, bbo, &cfgs, |cfg, aw, ports| {
        let l = usize::from(cfg.lane.0);
        let mut acct = AcctRisk::new(AccountId(1), AccountId(1));
        acct.max_open_orders = 1000;
        let mut lane = Lane::<Hw, NA>::new(cfg, aw, ports, acct);
        for a in 1..NA as u32 {
            let (risk, bal) = lane.account_mut(AcctSlot(a)).unwrap();
            risk.account = account(l, a);
            risk.master = master(a).unwrap_or(account(l, a));
            risk.fees = rates(a);
            bal.quote_free = 1 << 60;
            bal.base_free = 1 << 40;
            assert!(lane.open_session(&SessionSpec {
                id: sid(l, a),
                acct: AcctSlot(a),
                k_seq: kseq(l, a),
                book: BOOK,
                buckets: SessionBuckets::default(),
            }));
        }
        lane
    })
    .unwrap()
}

#[derive(Clone)]
struct View(PubKey);

impl EpochView for View {
    fn epoch(&self) -> Epoch {
        Epoch(0)
    }
    fn book(&self) -> vyrn_types::BookId {
        BOOK
    }
    fn seq_key(&self, sender: u8) -> Option<PubKey> {
        (sender == 0).then_some(self.0)
    }
    fn fenced(&self, _: Height) -> bool {
        false
    }
}

/// Makers on three accounts (two under one master), a cross, a forwarded IOC that is shed,
/// a cancel, a sweep over a `CONT` run that leaves a residual, reduces, a shed packet and its
/// resend, an IOC that partly fills the residual and is `Out` for the rest, and a heartbeat-only
/// packet and a join behind a heartbeat.
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
        // 05 §6.8: shed at the lane, then resent.
        p(0, 4, 10_000, 10_462, vec![new(Sell, Day, 300, 1, 9)]),
        p(0, 4, 20_000, 20_461, vec![new(Sell, Day, 300, 1, 9)]),
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
        p(2, 3, 32_000, 32_000, vec![new(Buy, Day, 111, 7, 30)]),
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
        p(1, 5, 36_000, 36_000, vec![new(Sell, Ioc, 111, 5, 60)]),
        Act::Run,
        // Session-only messages take no LaneSeq (#112): a heartbeat-only packet, then a join
        // behind a heartbeat, whose Ack names message index 1.
        p(0, 3, 37_000, 37_000, vec![Msg::Heartbeat]),
        p(
            0,
            3,
            37_100,
            37_100,
            vec![Msg::Heartbeat, new(Sell, Day, 120, 1, 50)],
        ),
        Act::Run,
    ]
}

fn prefix(h: &Hash) -> PktHash {
    PktHash(u64::from_le_bytes(h.0[..8].try_into().unwrap()))
}

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
    fn tx(&mut self, h: &vyrn_bbo::TxEntry, recs: &[Resp]) {
        self.0.tx(h, recs);
        self.1.tx(h, recs);
    }
}

/// Drop-copy output and the engine's summed `fee_acc`.
struct Run {
    recs: Recs,
    fee_acc: i128,
}

fn live(script: &[Act]) -> (Journal, Store, Run) {
    let (bbo, mut sh) = new_box();
    let mut e = fee_engine(bbo, &mut sh);
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
                s.1.payload(&bytes);
                let rx = RxIn {
                    bytes: &bytes,
                    rx_ts: Nanos(*rx_ts),
                    pkt_hash: prefix(&full_hash(&bytes)),
                };
                let r = e.ingest(*l, rx, &FixedClock(*now), &mut s).unwrap();
                let seq = pkt[*l][ai];
                if r == Rx::Shed {
                    pkt[*l][ai] -= 1;
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
    let fee_acc = (0..N).map(|l| e.lane(l).unwrap().book_acc().fee_acc).sum();
    let (_, dc) = m.finish_tap().unwrap();
    assert_eq!(dc.error(), None);
    let recs = dc.finish(|_| Default::default()).unwrap();
    (j, store, Run { recs, fee_acc })
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
    std::iter::from_fn(|| core.take_ready()).collect()
}

/// `RustReplay` over `blocks`, each block final right after it replays.
fn replay(live_j: &Journal, store: &Store, blocks: &[BlockInputs<N>]) -> Result<Run, ReplayError> {
    let mut data = DataJoin::default();
    for ((_, s, q, _), b) in &store.0 {
        data.put(*s, *q, b.clone());
    }
    let (bbo, mut sh) = new_box();
    let e = fee_engine(bbo, &mut sh);
    let mut rep = RustReplay::new(e, data, RespLog::of(live_j), md());
    for b in blocks {
        rep.payloads_mut().check(b).unwrap();
        let (p, m) = rep.payloads_and_sink();
        m.prepare(b, p);
        rep.replay_block(b)?;
        rep.release(b.header.height);
        rep.payloads_and_sink()
            .1
            .tap_mut()
            .final_block(b.header.height, b.header.last_step);
    }
    rep.finish()?;
    let fee_acc = (0..N)
        .map(|l| rep.engine().lane(l).unwrap().book_acc().fee_acc)
        .sum();
    let (_, dc) = rep.into_sink().finish_tap().unwrap();
    assert_eq!(dc.error(), None);
    let recs = dc.finish(|_| Default::default()).unwrap();
    Ok(Run { recs, fee_acc })
}

/// Every record but `DC_FINAL` / `DC_SETTLED`, per stream, in order.
fn canonical(recs: &Recs) -> BTreeMap<StreamId, Vec<DcRecord>> {
    let mut m: BTreeMap<StreamId, Vec<DcRecord>> = BTreeMap::new();
    for (s, _, r) in recs {
        if !r.kind().is_stage() {
            m.entry(*s).or_default().push(*r);
        }
    }
    m
}

fn check_streams(recs: &Recs) {
    let mut by: BTreeMap<StreamId, Vec<(u64, DcRecord)>> = BTreeMap::new();
    for (s, q, r) in recs {
        by.entry(*s).or_default().push((*q, *r));
    }
    for (s, v) in &by {
        for (i, (q, _)) in v.iter().enumerate() {
            assert_eq!(*q, i as u64 + 1, "{s:?}: gapless from 1");
        }
        let canon: Vec<_> = v.iter().filter(|(_, r)| !r.kind().is_stage()).collect();
        let (_, last) = canon.last().unwrap();
        assert_eq!((last.kind(), last.ordinal()), (DcType::Eod, EOD_HASH));
        let mut h = blake3::Hasher::new();
        for (_, r) in &canon[..canon.len() - 1] {
            h.update(&r.0);
        }
        assert_eq!(last.hash(), *h.finalize().as_bytes(), "{s:?}: stream hash");
        assert_eq!(last.word(0), canon.len() as u64 - 1);
    }
}

/// The live client records against the drop copy (module docs).
fn reconcile(j: &Journal, recs: &Recs) {
    // Client records by (session, resp_seq); maker TX packets (resp_seq 0) by (session, step).
    let mut client: Vec<(u32, u32, u64, Resp, bool)> = Vec::new();
    for (_, p) in &j.resp {
        for r in p.records() {
            client.push((p.session.0, p.resp_seq, 0, *r, false));
        }
    }
    for (h, rs) in &j.tx {
        for r in rs {
            let step = if h.resp_seq == 0 { h.step.0 } else { 0 };
            client.push((h.session.0, h.resp_seq, step, *r, false));
        }
    }
    client.retain(|c| !matches!(c.3, Resp::Reject { .. }));
    let own: Vec<DcRecord> = recs
        .iter()
        .filter(|(s, _, r)| !s.master && !matches!(r.kind(), DcType::Final | DcType::Eod))
        .map(|x| x.2)
        .collect();
    // Taker fills per level: (session, resp_seq, handle, tick) → summed qty.
    let mut taker: BTreeMap<(u32, u32, u32, u32), u32> = BTreeMap::new();
    let mut n_fills = 0;
    for r in &own {
        let (s, rs) = (r.session().0, r.resp_seq());
        if r.kind() == DcType::Fill && r.taker() {
            *taker.entry((s, rs, r.handle().0, r.tick().0)).or_default() += r.qty().0;
            n_fills += 1;
            continue;
        }
        // A TX-core packet without a reservation carries resp_seq 0 here (10 §8.4 item 4):
        // a DC_FILL then also names its step; other records match on their fields.
        let want_step = (rs == 0 && r.kind() == DcType::Fill).then(|| r.step());
        let hit = client.iter_mut().find(|c| {
            !c.4 && (c.0, c.1) == (s, rs)
                && want_step.is_none_or(|w| w == c.2)
                && match (r.kind(), c.3) {
                    (
                        DcType::Ack,
                        Resp::Ack {
                            index,
                            handle,
                            tick,
                            client_tag,
                        },
                    ) => {
                        (u16::from(index), handle, tick, client_tag)
                            == (r.ordinal(), r.handle(), r.tick(), r.client_tag())
                    }
                    (
                        DcType::Cancel,
                        Resp::CancelAck {
                            index,
                            handle,
                            canceled,
                            client_tag,
                        },
                    ) => {
                        (u16::from(index), handle, canceled, client_tag)
                            == (r.ordinal(), r.handle(), r.qty(), r.client_tag())
                    }
                    (
                        DcType::Out,
                        Resp::Out {
                            index,
                            handle,
                            qty,
                            client_tag,
                            ..
                        },
                    ) => {
                        (u16::from(index), handle, qty, client_tag)
                            == (r.ordinal(), r.handle(), r.qty(), r.client_tag())
                    }
                    (
                        DcType::Fill,
                        Resp::Fill {
                            handle, tick, qty, ..
                        },
                    ) => (handle, tick, qty) == (r.handle(), r.tick(), r.qty()),
                    _ => false,
                }
        });
        match hit {
            Some(c) => c.4 = true,
            None => panic!("no client record for {:?} {r:?}", r.kind()),
        }
        n_fills += usize::from(r.kind() == DcType::Fill);
    }
    for ((s, rs, h, t), q) in taker {
        let c = client
            .iter_mut()
            .find(|c| {
                !c.4 && (c.0, c.1) == (s, rs)
                    && matches!(c.3, Resp::Fill { handle, tick, qty, .. }
                        if (handle.0, tick.0, qty.0) == (h, t, q))
            })
            .unwrap_or_else(|| panic!("no taker Fill {s:#x}/{rs} @{t} x{q}"));
        c.4 = true;
    }
    let left: Vec<_> = client.iter().filter(|c| !c.4).collect();
    assert!(
        left.is_empty(),
        "client records without a drop copy: {left:?}"
    );
    assert!(n_fills >= 8, "the script fills: {n_fills}");
}

fn fees(recs: &Recs) -> i128 {
    recs.iter()
        .filter(|(s, _, r)| !s.master && r.kind() == DcType::Eod && r.ordinal() == 1)
        .map(|(_, _, r)| i128::from(r.word(0) as i64) + i128::from(r.word(1)))
        .sum()
}

#[test]
fn replay_drop_copy_equals_live_and_the_response_stream() {
    let (j, store, live) = live(&script());
    check_streams(&live.recs);
    reconcile(&j, &live.recs);
    assert_eq!(
        fees(&live.recs),
        live.fee_acc,
        "fees on the streams = fee_acc"
    );
    assert_ne!(live.fee_acc, 0);
    let want = canonical(&live.recs);
    assert!(want.keys().any(|s| s.master), "a master stream");
    for at in std::iter::once(None).chain((0..j.recs.len() - 1).map(Some)) {
        let cuts: Vec<usize> = at.into_iter().collect();
        let bs = blocks(&j, &store, &cuts);
        let rep = replay(&j, &store, &bs).unwrap_or_else(|e| panic!("split {at:?}: {e}"));
        assert_eq!(canonical(&rep.recs), want, "split {at:?}");
        assert_eq!(rep.fee_acc, live.fee_acc);
        check_streams(&rep.recs);
        // Every DC_FINAL names a step the stream had reached; one per block at most.
        let finals = rep
            .recs
            .iter()
            .filter(|(_, _, r)| r.kind() == DcType::Final)
            .count();
        assert!(finals > 0, "split {at:?}: DC_FINAL");
        let mut last: BTreeMap<StreamId, u64> = BTreeMap::new();
        for (s, _, r) in &rep.recs {
            match r.kind() {
                DcType::Fill => {
                    last.insert(*s, r.step());
                }
                DcType::Final => assert!(last.get(s).is_none_or(|x| *x <= r.step())),
                _ => {}
            }
        }
    }
}
