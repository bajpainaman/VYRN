//! Property tests of the order-stream codec.
//!
//! - Round trip: a model builds a random valid substream (binds, packets, Advance records,
//!   AcctTakes, home and cut-only steps in every cut mode, marks, hash runs, heartbeats,
//!   headers, padding); the encoder accepts it, and the decoder returns the same bodies.
//! - Canonical encoding: every frame the decoder accepts, whether mutated or random bytes,
//!   re-encodes from the same state to exactly the bytes it was given.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, VecDeque};

use proptest::prelude::*;
use vyrn_log::frame::with_flags;
use vyrn_log::stream::{has_payload, has_src};
use vyrn_log::{
    BlockMark, Body, FrameHeader, Heartbeat, Home, Ident, LaneBase, LaneRec, Layout, Section,
    SessionBind, StepHalf, StreamDecoder, StreamEncoder, TenureStart,
};
use vyrn_types::{
    AccountId, AcctTake, BlockHeader, BookId, Epoch, Hash, Height, LaneId, LaneSeq, Nanos,
    PacketFlags, PacketRecord, PktHash, SessionId, StepId, StepKind,
};

/// A deterministic source of choices from proptest's random words.
struct Pick(VecDeque<u64>);

impl Pick {
    fn n(&mut self, bound: u64) -> u64 {
        let v = self.0.pop_front().unwrap_or(0x9E37_79B9_7F4A_7C15);
        self.0.push_back(v.rotate_left(17) ^ 0xD6E8_FEB8_6659_FD93);
        if bound == 0 { 0 } else { v % bound }
    }
    fn coin(&mut self) -> bool {
        self.n(2) == 0
    }
}

#[derive(Default, Clone)]
struct Table {
    slot: BTreeMap<u16, (u32, u32)>,
    of: BTreeMap<u32, u16>,
}

struct LaneM {
    next: u64,
    rx: u64,
    fa: u64,
    awaiting: VecDeque<u64>,
    table: usize,
}

struct Model {
    layout: Layout,
    stream: u8,
    lanes: Vec<u8>,
    lm: Vec<LaneM>,
    tables: Vec<Table>,
    prev_step: u64,
    prev_cut: Vec<u64>,
    mark_step: u64,
    next_height: u64,
}

const KINDS: [StepKind; 9] = [
    StepKind::Cross,
    StepKind::Improve,
    StepKind::Depletion,
    StepKind::Rescan,
    StepKind::Idle,
    StepKind::Shed,
    StepKind::Control,
    StepKind::Seal,
    StepKind::Uncross,
];

impl Model {
    fn tenure(layout: Layout, stream: u8, p: &mut Pick) -> (Self, TenureStart) {
        let lanes: Vec<u8> = layout.half(stream).collect();
        let mut tables = Vec::new();
        let mut pool = None;
        let mut lm = Vec::new();
        let mut bases = Vec::new();
        for &l in &lanes {
            let table = if layout.is_pool(l) {
                *pool.get_or_insert_with(|| {
                    tables.push(Table::default());
                    tables.len() - 1
                })
            } else {
                tables.push(Table::default());
                tables.len() - 1
            };
            let b = LaneBase {
                next_lane_seq: LaneSeq(1 + p.n(1000)),
                rx_ts: Nanos(p.n(1 << 40)),
                fills_applied: StepId(p.n(50)),
            };
            lm.push(LaneM {
                next: b.next_lane_seq.0,
                rx: b.rx_ts.0,
                fa: b.fills_applied.0,
                awaiting: VecDeque::new(),
                table,
            });
            bases.push(b);
        }
        let prev_cut: Vec<u64> = lanes.iter().map(|_| p.n(300)).collect();
        let first_step = 1 + p.n(1000);
        let first_height = p.n(1 << 20);
        let ts = TenureStart {
            epoch: Epoch(p.n(1 << 32) as u32),
            tenure: p.n(4) as u8,
            sender: p.n(4) as u8,
            first_step: StepId(first_step),
            first_height: Height(first_height),
            prev_header_hash: Hash([p.n(256) as u8; 32]),
            lanes: bases,
            prev_cut: prev_cut.iter().map(|&c| LaneSeq(c)).collect(),
        };
        let m = Self {
            layout,
            stream,
            lanes,
            lm,
            tables,
            prev_step: first_step - 1,
            prev_cut,
            mark_step: first_step - 1,
            next_height: first_height,
        };
        (m, ts)
    }

    fn bind(&mut self, p: &mut Pick) -> Section {
        let i = p.n(self.lanes.len() as u64) as usize;
        let slot = p.n(6) as u16;
        let session = 1 + p.n(8) as u32;
        let next = p.n(1000) as u32;
        let t = &mut self.tables[self.lm[i].table];
        if let Some((old, _)) = t.slot.remove(&slot) {
            t.of.remove(&old);
        }
        if let Some(prev) = t.of.insert(session, slot) {
            t.slot.remove(&prev);
        }
        t.slot.insert(slot, (session, next));
        Section::SessionBind(SessionBind {
            lane: LaneId(self.lanes[i]),
            slot,
            session: SessionId(session),
            next_pkt_seq: next,
        })
    }

    fn lane_run(&mut self, p: &mut Pick) -> Option<Section> {
        let i = p.n(self.lanes.len() as u64) as usize;
        let lane = self.lanes[i];
        let mut recs = Vec::new();
        for _ in 0..1 + p.n(3) {
            let choice = p.n(10);
            let l = &mut self.lm[i];
            if choice == 0 && self.layout.is_pool(lane) {
                recs.push(LaneRec::Take(AcctTake {
                    lane: LaneId(lane),
                    account: AccountId(p.n(1 << 32) as u32),
                    ver: p.n(1 << 32) as u32,
                    lane_seq: LaneSeq(l.next),
                }));
                continue;
            }
            let rx = if p.coin() {
                l.rx + p.n(5000)
            } else {
                l.rx.saturating_sub(p.n(5000))
            };
            let fa = l.fa + if p.n(3) == 0 { p.n(4) } else { 0 };
            let t = &mut self.tables[l.table];
            if choice == 1 || t.slot.is_empty() {
                let rec = PacketRecord {
                    lane: LaneId(lane),
                    count: 0,
                    flags: PacketFlags::ADVANCE,
                    session: SessionId(0),
                    pkt_seq: 0,
                    rx_ts: Nanos(rx),
                    pkt_hash: PktHash(0),
                    first_lane_seq: LaneSeq(l.next),
                    fills_applied: StepId(fa),
                };
                (l.rx, l.fa) = (rx, fa);
                recs.push(LaneRec::Pkt(rec));
                continue;
            }
            let k = p.n(t.slot.len() as u64) as usize;
            let (&slot, &(session, next)) = t.slot.iter().nth(k).unwrap();
            let pkt_seq = if p.n(4) == 0 { p.n(2000) as u32 } else { next };
            t.slot.insert(slot, (session, pkt_seq + 1));
            let count = p.n(11) as u8;
            let first = l.next + if p.n(4) == 0 { p.n(5) } else { 0 };
            let rec = PacketRecord {
                lane: LaneId(lane),
                count,
                flags: if p.n(5) == 0 { PacketFlags::SHED } else { 0 },
                session: SessionId(session),
                pkt_seq,
                rx_ts: Nanos(rx),
                pkt_hash: PktHash(0),
                first_lane_seq: LaneSeq(first),
                fills_applied: StepId(fa),
            };
            (l.rx, l.fa, l.next) = (rx, fa, first + u64::from(count));
            l.awaiting.push_back(first);
            recs.push(LaneRec::Pkt(rec));
        }
        Some(Section::LaneRun {
            lane: LaneId(lane),
            recs,
        })
    }

    fn step(&mut self, p: &mut Pick) -> StepHalf {
        let two = self.layout.streams() == 2;
        let cut_only = two && p.n(4) == 0;
        let mut cut = self.prev_cut.clone();
        let moves = p.n(4);
        for _ in 0..moves {
            let i = p.n(cut.len() as u64) as usize;
            let big = p.coin();
            cut[i] += 1 + p.n(if big { 300 } else { 3 });
        }
        if cut_only && cut == self.prev_cut {
            cut[0] += 1;
        }
        let step = self.prev_step.max(self.mark_step) + 1 + p.n(3);
        let mut kind = KINDS[p.n(9) as usize];
        if self.stream == 1 && !cut_only && !has_src(kind) {
            kind = StepKind::Improve;
        }
        let home = (!cut_only).then(|| {
            if has_src(kind) {
                let i = p.n(cut.len() as u64) as usize;
                let seq = (cut[i] + p.n(20)).saturating_sub(10).max(1);
                Home {
                    src_lane: LaneId(self.lanes[i]),
                    src_lane_seq: LaneSeq(seq),
                    payload: vec![],
                }
            } else {
                let n = if has_payload(kind) { p.n(6) } else { 0 };
                Home {
                    src_lane: LaneId(0xFF),
                    src_lane_seq: LaneSeq(0),
                    payload: (0..n).map(|_| p.n(256) as u8).collect(),
                }
            }
        });
        self.prev_step = step;
        self.prev_cut.clone_from(&cut);
        StepHalf {
            step: StepId(step),
            kind,
            other: cut_only || (two && p.n(3) == 0),
            home,
            cut: cut.into_iter().map(LaneSeq).collect(),
        }
    }

    fn mark(&mut self, p: &mut Pick) -> Section {
        let last = self.prev_step.max(self.mark_step) + p.n(3);
        let m = BlockMark {
            height: Height(self.next_height),
            last_step: StepId(last),
            lane_bounds: self.lm.iter().map(|l| LaneSeq(l.next - 1)).collect(),
        };
        self.next_height += 1;
        self.mark_step = last;
        Section::BlockMark(m)
    }

    fn hash_run(&mut self, p: &mut Pick) -> Option<Section> {
        let i = p.n(self.lanes.len() as u64) as usize;
        let l = &mut self.lm[i];
        if l.awaiting.is_empty() {
            return None;
        }
        let k = 1 + p.n(l.awaiting.len() as u64) as usize;
        let entries = l
            .awaiting
            .drain(..k)
            .map(|s| (LaneSeq(s), PktHash(p.n(u64::MAX))))
            .collect();
        Some(Section::HashRun {
            lane: LaneId(self.lanes[i]),
            entries,
        })
    }
}

fn layouts() -> [(Layout, u8); 3] {
    let two = Layout::new(5, 2, 0b11000).unwrap(); // A = 0-2, B = 3-4 (pooled)
    let one = Layout::new(3, 1, 0b100).unwrap();
    [(two, 0), (two, 1), (one, 0)]
}

/// A random valid substream: its layout, stream, ident and frame bodies.
fn substream(which: usize, words: Vec<u64>) -> (Layout, u8, Ident, Vec<Body>) {
    let (layout, stream) = layouts()[which];
    let mut p = Pick(words.into());
    let (mut m, ts) = Model::tenure(layout, stream, &mut p);
    let ident = Ident {
        book: BookId(p.n(1 << 16) as u16),
        epoch: ts.epoch,
        tenure: ts.tenure,
        sender: ts.sender,
    };
    let mut bodies = Vec::new();
    let mut order = Vec::new();
    let mut tenure = Some(ts);
    for _ in 0..40 {
        match p.n(12) {
            0 => order.push(m.bind(&mut p)),
            1..=4 => order.extend(m.lane_run(&mut p)),
            5 | 6 => order.push(Section::StepRun(
                (0..1 + p.n(3)).map(|_| m.step(&mut p)).collect(),
            )),
            7 => order.push(m.mark(&mut p)),
            _ => {
                if p.n(4) == 0 {
                    order.push(Section::Pad(p.n(5) as usize));
                }
                bodies.push(Body::Order {
                    tenure_start: tenure.take(),
                    sections: core::mem::take(&mut order),
                });
                match p.n(4) {
                    0 => {
                        let runs: Vec<_> = (0..3).filter_map(|_| m.hash_run(&mut p)).collect();
                        bodies.push(Body::Hash(runs));
                    }
                    1 => bodies.push(Body::Heartbeat(Heartbeat {
                        last_step: StepId(p.n(u64::MAX)),
                        last_height: Height(p.n(u64::MAX)),
                        ptp_now: Nanos(p.n(u64::MAX)),
                    })),
                    2 if stream == 0 => bodies.push(Body::Header(BlockHeader {
                        height: Height(p.n(u64::MAX)),
                        epoch: Epoch(7),
                        book: BookId(1),
                        first_step: StepId(p.n(99)),
                        last_step: StepId(p.n(99)),
                        prev: Hash([1; 32]),
                        order_root: Hash([2; 32]),
                        data_root: Hash([3; 32]),
                        seq_sig: [p.n(256) as u8; 64],
                    })),
                    _ => {}
                }
            }
        }
    }
    bodies.push(Body::Order {
        tenure_start: tenure.take(),
        sections: order,
    });
    (layout, stream, ident, bodies)
}

fn encode_all(layout: Layout, stream: u8, ident: Ident, bodies: &[Body]) -> Vec<Vec<u8>> {
    let mut enc = StreamEncoder::new(layout, stream, ident).unwrap();
    bodies
        .iter()
        .map(|b| {
            enc.encode(b)
                .unwrap_or_else(|e| panic!("encoder rejected valid {b:?}: {e}"))
        })
        .collect()
}

/// Decodes `frames` in order; each frame that decodes must re-encode, from the same state, to
/// exactly its bytes. Stops at the first frame that does not decode.
fn check_canonical(layout: Layout, stream: u8, frames: &[Vec<u8>]) -> usize {
    let mut dec = StreamDecoder::new(layout, stream).unwrap();
    let mut enc: Option<StreamEncoder> = None;
    for (n, f) in frames.iter().enumerate() {
        let Ok(frame) = dec.decode(f) else { return n };
        if let Body::Order {
            tenure_start: Some(ts),
            ..
        } = &frame.body
        {
            let id = Ident {
                book: frame.header.book,
                epoch: ts.epoch,
                tenure: frame.header.tenure,
                sender: frame.header.sender,
            };
            enc = Some(StreamEncoder::new(layout, stream, id).unwrap());
        }
        let again = enc
            .as_mut()
            .unwrap()
            .encode(&frame.body)
            .unwrap_or_else(|e| {
                panic!(
                    "accepted frame {n} does not re-encode ({e}): {:?}",
                    frame.body
                )
            });
        assert_eq!(
            with_flags(&again, frame.header.flags),
            *f,
            "frame {n} is not canonical"
        );
    }
    frames.len()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn round_trip(which in 0usize..3, words in prop::collection::vec(any::<u64>(), 64..256)) {
        let (layout, stream, ident, bodies) = substream(which, words);
        let frames = encode_all(layout, stream, ident, &bodies);
        let mut dec = StreamDecoder::new(layout, stream).unwrap();
        for (f, b) in frames.iter().zip(&bodies) {
            let got = dec.decode(f).unwrap();
            prop_assert_eq!(&got.body, b);
            prop_assert_eq!(FrameHeader::parse(f).unwrap().0, got.header);
        }
        prop_assert_eq!(check_canonical(layout, stream, &frames), frames.len());
    }

    #[test]
    fn mutated_frames_are_rejected_or_canonical(
        which in 0usize..3,
        words in prop::collection::vec(any::<u64>(), 64..256),
        at in any::<prop::sample::Index>(),
        byte in any::<prop::sample::Index>(),
        how in 0u8..4,
        val in any::<u8>(),
    ) {
        let (layout, stream, ident, bodies) = substream(which, words);
        let mut frames = encode_all(layout, stream, ident, &bodies);
        let i = at.index(frames.len());
        let f = &mut frames[i];
        let j = byte.index(f.len());
        match how {
            0 => f[j] ^= val | 1,
            1 => f[j] = val,
            2 => f.truncate(j),
            _ => f.insert(j, val),
        }
        // Keep body_len consistent half the time so that body bytes are what gets tested.
        if how >= 2 && val & 1 == 0 && f.len() >= 24 {
            let n = u16::try_from(f.len() - 24).unwrap_or(0).to_le_bytes();
            f[18] = n[0];
            f[19] = n[1];
        }
        check_canonical(layout, stream, &frames);
    }

    #[test]
    fn random_bodies_are_rejected_or_canonical(
        which in 0usize..3,
        words in prop::collection::vec(any::<u64>(), 64..128),
        kind in 1u8..5,
        body in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let (layout, stream, ident, bodies) = substream(which, words);
        let mut frames = encode_all(layout, stream, ident, &bodies[..1]);
        let mut f = frames[0][..24].to_vec();
        f[3] = kind;
        f[8..16].copy_from_slice(&2u64.to_le_bytes());
        f[18..20].copy_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        f.extend(body);
        frames.push(f);
        check_canonical(layout, stream, &frames);
    }
}
