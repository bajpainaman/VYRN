//! `SeqWriter` against this crate's own decoder: every frame it emits decodes in order, the
//! decoded lane records and steps are the ones pushed (hashes from the `HashRun`), and the
//! header chains from the tenure anchor, commits to the block's ORDER bytes and data, and
//! verifies under the seed's key. A second block chains from the first.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use vyrn_log::block::{data_root, order_root, verify_seq_sig};
use vyrn_log::{
    Body, Ident, LaneBase, LaneRec, Layout, Section, SeqWriter, StreamDecoder, TenureStart,
    check_link, header_hash,
};
use vyrn_types::{
    BookId, Epoch, Hash, Height, LaneId, LaneSeq, Nanos, PacketFlags, PacketRecord, PktHash,
    SessionId, StepId, StepKind,
};

const SEED: [u8; 32] = [7; 32];

fn ts() -> TenureStart {
    TenureStart {
        epoch: Epoch(3),
        tenure: 0,
        sender: 0,
        first_step: StepId(1),
        first_height: Height(0),
        prev_header_hash: Hash([9; 32]),
        lanes: vec![
            LaneBase {
                next_lane_seq: LaneSeq(1),
                rx_ts: Nanos(0),
                fills_applied: StepId(0),
            };
            3
        ],
        prev_cut: vec![LaneSeq(0); 3],
    }
}

fn pkt(lane: u8, session: u32, seq: u32, first: u64, count: u8) -> PacketRecord {
    PacketRecord {
        lane: LaneId(lane),
        count,
        flags: 0,
        session: SessionId(session),
        pkt_seq: seq,
        rx_ts: Nanos(5_000 + first),
        pkt_hash: PktHash(0xA000 + first),
        first_lane_seq: LaneSeq(first),
        fills_applied: StepId(0),
    }
}

#[test]
fn frames_decode_and_headers_chain() {
    let layout = Layout::new(3, 1, 0).unwrap();
    let ident = Ident {
        book: BookId(2),
        epoch: Epoch(3),
        tenure: 0,
        sender: 0,
    };
    let mut w = SeqWriter::new(layout, ident, ts(), SEED).unwrap();
    let mut frames = Vec::new();
    // Block 0: two packets on lane 2 (same session, second pkt_seq predicted), one on lane 0,
    // an Improve; then an Advance record on lane 2 after a step that filled it.
    let pushed = [
        pkt(2, 0x11, 1, 1, 2),
        pkt(2, 0x11, 2, 3, 1),
        pkt(0, 0x22, 9, 1, 1),
    ];
    for p in pushed {
        frames.extend(
            w.packet(p, Some(Hash([p.first_lane_seq.0 as u8; 32])))
                .unwrap(),
        );
    }
    let cut = [LaneSeq(1), LaneSeq(0), LaneSeq(3)];
    frames.extend(
        w.step(
            StepId(1),
            StepKind::Improve,
            Some((LaneId(2), LaneSeq(3))),
            Vec::new(),
            &cut,
        )
        .unwrap(),
    );
    let adv = PacketRecord {
        lane: LaneId(2),
        count: 0,
        flags: PacketFlags::ADVANCE,
        session: SessionId(0),
        pkt_seq: 0,
        rx_ts: Nanos(9_000),
        pkt_hash: PktHash(0),
        first_lane_seq: LaneSeq(4),
        fills_applied: StepId(1),
    };
    frames.extend(w.packet(adv, None).unwrap());
    let (f0, h0) = w.close_block().unwrap();
    frames.extend(f0);
    // Block 1: one step, no packets.
    frames.extend(
        w.step(StepId(2), StepKind::Idle, None, Vec::new(), &cut)
            .unwrap(),
    );
    let (f1, h1) = w.close_block().unwrap();
    frames.extend(f1);

    let mut dec = StreamDecoder::new(layout, 0).unwrap();
    let mut recs = Vec::new();
    let mut hashes = Vec::new();
    let mut headers = Vec::new();
    for f in &frames {
        match dec.decode(f).unwrap().body {
            Body::Order { sections, .. } => {
                for s in sections {
                    if let Section::LaneRun { recs: r, .. } = s {
                        recs.extend(r);
                    }
                }
            }
            Body::Hash(sections) => {
                for s in sections {
                    if let Section::HashRun { entries, .. } = s {
                        hashes.extend(entries);
                    }
                }
            }
            Body::Header(h) => headers.push(h),
            Body::Heartbeat(_) => panic!("no heartbeats"),
        }
    }
    let want: Vec<LaneRec> = pushed
        .iter()
        .map(|p| {
            LaneRec::Pkt(PacketRecord {
                pkt_hash: PktHash(0),
                ..*p
            })
        })
        .chain([LaneRec::Pkt(adv)])
        .collect();
    assert_eq!(recs, want);
    // One HashRun per lane in lane order, each in FIFO order; the Advance record waits for none.
    let want_h = [
        (LaneSeq(1), PktHash(0xA001)), // lane 0
        (LaneSeq(1), PktHash(0xA001)), // lane 2
        (LaneSeq(3), PktHash(0xA003)),
    ];
    assert_eq!(hashes, want_h);

    assert_eq!(headers, vec![h0, h1]);
    let pk = vyrn_crypto::ed25519::public_key(&SEED);
    assert!(verify_seq_sig(&h0, &pk) && verify_seq_sig(&h1, &pk));
    assert_eq!(h0.prev, Hash([9; 32]));
    assert_eq!(
        (h0.height, h0.first_step, h0.last_step),
        (Height(0), StepId(1), StepId(1))
    );
    assert_eq!(
        (h1.height, h1.first_step, h1.last_step),
        (Height(1), StepId(2), StepId(2))
    );
    check_link(&h0, &h1).unwrap();
    assert_eq!(h1.prev, header_hash(&h0));
    // Block 0 carries three data hashes in O-order; block 1 none.
    let full: Vec<Hash> = [1u8, 3, 1].iter().map(|b| Hash([*b; 32])).collect();
    assert_eq!(h0.data_root, data_root(&full, &[]));
    assert_eq!(h1.data_root, data_root(&[], &[]));
    assert_ne!(h0.order_root, order_root(&[], &[]));
}

#[test]
fn two_substreams_are_refused() {
    let ident = Ident {
        book: BookId(2),
        epoch: Epoch(3),
        tenure: 0,
        sender: 0,
    };
    assert!(SeqWriter::new(Layout::new(4, 2, 0).unwrap(), ident, ts(), SEED).is_err());
}
