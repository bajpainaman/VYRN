//! `tests/golden/vyrn_log_vectors.out` is the output of `python3 -I vyrn_log_vectors.py`, which
//! writes every byte by hand from 07's tables and hashes with its own BLAKE3. This test
//! rebuilds each vector with vyrn-log, compares byte for byte, and decodes each one back.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

use vyrn_log::block::{self, BlockAssembler, data_root, encode_header, order_root};
use vyrn_log::frame::{FrameFlags, with_flags};
use vyrn_log::leb::{self, Reader};
use vyrn_log::store::{Block, BlockKind, decode_record, encode_record};
use vyrn_log::{
    BlockMark, Body, BodyKind, Heartbeat, Home, Ident, LaneBase, LaneRec, Layout, RepErr, Section,
    SessionBind, StepHalf, StepMerger, StreamDecoder, StreamEncoder, SubstreamState, TenureStart,
};
use vyrn_types::{
    AccountId, AcctTake, BlockHeader, BookId, Epoch, Hash, Height, LaneId, LaneSeq, Nanos,
    PacketFlags, PacketRecord, PktHash, SessionId, StepId, StepKind,
};

fn golden() -> BTreeMap<String, String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/vyrn_log_vectors.out"
    );
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let (k, v) = l.split_once(": ").unwrap_or((l.trim_end_matches(':'), ""));
            (k.to_owned(), v.to_owned())
        })
        .collect()
}

fn bytes(g: &BTreeMap<String, String>, k: &str) -> Vec<u8> {
    let h = g.get(k).unwrap_or_else(|| panic!("missing {k}"));
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn leb128_and_zigzag() {
    let g = golden();
    let mut n = 0;
    for k in g.keys() {
        if let Some(v) = k.strip_prefix("leb.") {
            let v: u64 = v.parse().unwrap();
            let mut out = Vec::new();
            leb::put_u64(&mut out, v);
            assert_eq!(out, bytes(&g, k), "{k}");
            assert_eq!(leb::decode_u64(&out).unwrap(), (v, out.len()));
            n += 1;
        } else if let Some(v) = k.strip_prefix("zigzag.") {
            let v: i64 = v.parse().unwrap();
            let mut out = Vec::new();
            leb::put_i64(&mut out, v);
            assert_eq!(out, bytes(&g, k), "{k}");
            assert_eq!(Reader::new(&out).leb_i64().unwrap(), v);
            n += 1;
        } else if k.starts_with("leb_bad.") {
            let b = bytes(&g, k);
            assert!(leb::decode_u64(&b).is_err(), "{k} must be rejected");
            n += 1;
        }
    }
    assert_eq!(n, 30);
}

fn ref_state() -> SubstreamState {
    let mut st = SubstreamState::new(Layout::reference(), 0).unwrap();
    st.apply_tenure_start(&TenureStart {
        epoch: Epoch(1),
        tenure: 0,
        sender: 0,
        first_step: StepId(1),
        first_height: Height(0),
        prev_header_hash: Hash::default(),
        lanes: vec![
            LaneBase {
                next_lane_seq: LaneSeq(1),
                rx_ts: Nanos(1_000_000),
                fills_applied: StepId(0),
            };
            25
        ],
        prev_cut: vec![LaneSeq(0); 25],
    })
    .unwrap();
    st
}

#[test]
fn worked_example_07_3_11() {
    let g = golden();
    let mut st = ref_state();
    let bind = Section::SessionBind(SessionBind {
        lane: LaneId(7),
        slot: 300,
        session: SessionId(42),
        next_pkt_seq: 1,
    });
    st.encode_sections(std::slice::from_ref(&bind), BodyKind::Order)
        .unwrap();
    let mut cut = vec![LaneSeq(0); 25];
    cut[3] = LaneSeq(2);
    cut[7] = LaneSeq(10);
    cut[12] = LaneSeq(1);
    let sections = vec![
        Section::LaneRun {
            lane: LaneId(7),
            recs: vec![LaneRec::Pkt(PacketRecord {
                lane: LaneId(7),
                count: 10,
                flags: 0,
                session: SessionId(42),
                pkt_seq: 1,
                rx_ts: Nanos(1_000_512),
                pkt_hash: PktHash(0),
                first_lane_seq: LaneSeq(1),
                fills_applied: StepId(0),
            })],
        },
        Section::StepRun(vec![StepHalf {
            step: StepId(1),
            kind: StepKind::Cross,
            other: false,
            home: Some(Home {
                src_lane: LaneId(7),
                src_lane_seq: LaneSeq(10),
                payload: vec![],
            }),
            cut,
        }]),
    ];
    let enc = st.encode_sections(&sections, BodyKind::Order).unwrap();
    assert_eq!(enc, bytes(&g, "ex311.sections"));
    assert_eq!(enc.len(), 20, "07 §3.11: 20 bytes");

    let mut dec = ref_state();
    dec.encode_sections(&[bind], BodyKind::Order).unwrap();
    assert_eq!(
        dec.decode_sections(&enc, BodyKind::Order).unwrap(),
        sections
    );
}

const PREV: Hash = Hash([0x11; 32]);

fn layout4() -> Layout {
    Layout::new(4, 2, 1 << 3).unwrap()
}

fn tenure_start() -> TenureStart {
    let base = LaneBase {
        next_lane_seq: LaneSeq(1),
        rx_ts: Nanos(1_000_000),
        fills_applied: StepId(0),
    };
    TenureStart {
        epoch: Epoch(1000),
        tenure: 0,
        sender: 0,
        first_step: StepId(1),
        first_height: Height(100),
        prev_header_hash: PREV,
        lanes: vec![base; 2],
        prev_cut: vec![LaneSeq(0); 2],
    }
}

fn pkt(lane: u8, count: u8, session: u32, pkt_seq: u32, rx: u64, first: u64, fa: u64) -> LaneRec {
    LaneRec::Pkt(PacketRecord {
        lane: LaneId(lane),
        count,
        flags: 0,
        session: SessionId(session),
        pkt_seq,
        rx_ts: Nanos(rx),
        pkt_hash: PktHash(0),
        first_lane_seq: LaneSeq(first),
        fills_applied: StepId(fa),
    })
}

fn bodies(g: &BTreeMap<String, String>) -> (Vec<Body>, Vec<Body>, BlockHeader) {
    let ph = |i: usize| {
        let p = bytes(g, &format!("blk.payload.{i}"));
        vyrn_crypto::pkt_hash(&p)
    };
    let mut advance = pkt(1, 0, 0, 0, 1_000_000, 1, 1);
    if let LaneRec::Pkt(p) = &mut advance {
        p.flags = PacketFlags::ADVANCE;
    }
    let a1 = Body::Order {
        tenure_start: Some(tenure_start()),
        sections: vec![
            Section::SessionBind(SessionBind {
                lane: LaneId(0),
                slot: 5,
                session: SessionId(0x0030_1007),
                next_pkt_seq: 1,
            }),
            Section::LaneRun {
                lane: LaneId(0),
                recs: vec![
                    pkt(0, 3, 0x0030_1007, 1, 1_000_700, 1, 0),
                    pkt(0, 1, 0x0030_1007, 5, 1_000_600, 4, 0),
                ],
            },
            Section::LaneRun {
                lane: LaneId(1),
                recs: vec![advance],
            },
            Section::StepRun(vec![
                StepHalf {
                    step: StepId(1),
                    kind: StepKind::Improve,
                    other: false,
                    home: Some(Home {
                        src_lane: LaneId(0),
                        src_lane_seq: LaneSeq(4),
                        payload: vec![],
                    }),
                    cut: vec![LaneSeq(4), LaneSeq(0)],
                },
                StepHalf {
                    step: StepId(2),
                    kind: StepKind::Control,
                    other: true,
                    home: Some(Home {
                        src_lane: LaneId(0xFF),
                        src_lane_seq: LaneSeq(0),
                        payload: vec![1, 2],
                    }),
                    cut: vec![LaneSeq(4), LaneSeq(0)],
                },
            ]),
            Section::BlockMark(BlockMark {
                height: Height(100),
                last_step: StepId(2),
                lane_bounds: vec![LaneSeq(4), LaneSeq(0)],
            }),
        ],
    };
    let a2 = Body::Hash(vec![Section::HashRun {
        lane: LaneId(0),
        entries: vec![(LaneSeq(1), ph(0)), (LaneSeq(4), ph(1))],
    }]);
    let header = BlockHeader {
        height: Height(100),
        epoch: Epoch(1000),
        book: BookId(1),
        first_step: StepId(1),
        last_step: StepId(2),
        prev: PREV,
        order_root: Hash(bytes(g, "blk.order_root").try_into().unwrap()),
        data_root: Hash(bytes(g, "blk.data_root").try_into().unwrap()),
        seq_sig: [0; 64],
    };
    let b1 = Body::Order {
        tenure_start: Some(tenure_start()),
        sections: vec![
            Section::SessionBind(SessionBind {
                lane: LaneId(3),
                slot: 0,
                session: SessionId(0x7003),
                next_pkt_seq: 1,
            }),
            Section::LaneRun {
                lane: LaneId(3),
                recs: vec![
                    LaneRec::Take(AcctTake {
                        lane: LaneId(3),
                        account: AccountId(9),
                        ver: 1,
                        lane_seq: LaneSeq(1),
                    }),
                    pkt(3, 2, 0x7003, 1, 1_000_050, 1, 0),
                ],
            },
            Section::StepRun(vec![StepHalf {
                step: StepId(2),
                kind: StepKind::Control,
                other: true,
                home: None,
                cut: vec![LaneSeq(0), LaneSeq(2)],
            }]),
            Section::BlockMark(BlockMark {
                height: Height(100),
                last_step: StepId(2),
                lane_bounds: vec![LaneSeq(0), LaneSeq(2)],
            }),
        ],
    };
    let b2 = Body::Hash(vec![Section::HashRun {
        lane: LaneId(3),
        entries: vec![(LaneSeq(1), ph(2))],
    }]);
    let b3 = Body::Heartbeat(Heartbeat {
        last_step: StepId(2),
        last_height: Height(100),
        ptp_now: Nanos(1_000_900),
    });
    (vec![a1, a2, Body::Header(header)], vec![b1, b2, b3], header)
}

#[test]
fn one_block_on_two_substreams() {
    let g = golden();
    let (a, b, header) = bodies(&g);
    let ident = Ident {
        book: BookId(1),
        epoch: Epoch(1000),
        tenure: 0,
        sender: 0,
    };
    let mut halves = Vec::new();
    let mut steps = Vec::new();
    for (stream, bodies, name) in [(0u8, &a, "a"), (1, &b, "b")] {
        let mut enc = StreamEncoder::new(layout4(), stream, ident).unwrap();
        let mut dec = StreamDecoder::new(layout4(), stream).unwrap();
        for (i, body) in bodies.iter().enumerate() {
            let key = format!("blk.frame.{name}{}", i + 1);
            let f = enc.encode(body).unwrap();
            assert_eq!(f, bytes(&g, &key), "{key}");
            let got = dec.decode(&f).unwrap();
            assert_eq!(&got.body, body, "{key} decodes back");
            if let Body::Order { sections, .. } = &got.body {
                for s in sections {
                    if let Section::StepRun(hs) = s {
                        steps.extend(hs.iter().cloned().map(|h| (stream, h)));
                    }
                }
            }
        }
        let closed = dec.take_closed();
        assert_eq!(closed, enc.take_closed());
        assert_eq!(closed.len(), 1);
        assert_eq!(
            closed[0].order_bytes,
            bytes(&g, &format!("blk.order_{name}"))
        );
        halves.extend(closed);
    }
    // Path B differs only in flags (INV-REP-3).
    let a1 = bytes(&g, "blk.frame.a1");
    assert_eq!(
        with_flags(&a1, FrameFlags::PATH_B),
        bytes(&g, "blk.frame.a1.path_b")
    );

    // The two half-records of step 2 merge into one StepRecord.
    let mut m = StepMerger::<4>::new(layout4(), StepId(1), [LaneSeq(0); 4]).unwrap();
    for (s, h) in steps {
        m.push(s, h).unwrap();
    }
    let s1 = m.pop().unwrap().unwrap();
    assert_eq!(
        (s1.rec.kind, s1.rec.src_lane, s1.rec.src_lane_seq),
        (StepKind::Improve, LaneId(0), LaneSeq(4))
    );
    assert_eq!(s1.rec.cut, [LaneSeq(4), LaneSeq(0), LaneSeq(0), LaneSeq(0)]);
    let s2 = m.pop().unwrap().unwrap();
    assert_eq!(
        (s2.rec.kind, s2.rec.src_lane, s2.payload.clone()),
        (StepKind::Control, LaneId(0xFF), vec![1, 2])
    );
    assert_eq!(s2.rec.cut, [LaneSeq(4), LaneSeq(0), LaneSeq(0), LaneSeq(2)]);
    assert_eq!(m.pop().unwrap(), None);

    // Roots, header and hash chain.
    let full: Vec<Hash> = (0..3)
        .map(|i| vyrn_crypto::hash::hash(&bytes(&g, &format!("blk.payload.{i}"))))
        .collect();
    let mut asm = BlockAssembler::from_tenure(BookId(1), &tenure_start());
    let built = asm
        .assemble(&halves[0], Some(&halves[1]), &full[..2], &full[2..])
        .unwrap();
    assert_eq!(built, header);
    assert_eq!(
        order_root(&halves[0].order_bytes, &halves[1].order_bytes),
        header.order_root
    );
    assert_eq!(data_root(&full[..2], &full[2..]), header.data_root);
    assert_eq!(encode_header(&header).to_vec(), bytes(&g, "blk.header"));
    assert_eq!(
        block::header_hash(&header).0.to_vec(),
        bytes(&g, "blk.header_hash")
    );
    assert_eq!(
        block::signing_message(&header),
        bytes(&g, "blk.seq_sig_message")
    );
    let seed = [7u8; 32];
    let signed = block::sign_header(&header, &seed);
    let key = vyrn_crypto::ed25519::public_key(&seed);
    assert!(block::verify_seq_sig(&signed, &key));
    assert_eq!(
        block::header_hash(&signed),
        block::header_hash(&header),
        "seq_sig is not hashed"
    );

    // The block record.
    let mut data = Vec::new();
    (0..3).for_each(|i| data.extend(bytes(&g, &format!("blk.payload.{i}"))));
    let blk = Block {
        header,
        tenure: 0,
        kind: BlockKind::Normal,
        order_a: halves[0].order_bytes.clone(),
        order_b: halves[1].order_bytes.clone(),
        pkt_hashes: halves
            .iter()
            .flat_map(|h| h.packets.iter())
            .zip(&full)
            .map(|(_, f)| PktHash(u64::from_le_bytes(f.0[..8].try_into().unwrap())))
            .collect(),
        data,
        unavailable: vec![],
    };
    let rec = encode_record(&blk).unwrap();
    assert_eq!(rec[..256].to_vec(), bytes(&g, "rec.head"));
    assert_eq!(rec.len().to_string(), g["rec.len"]);
    assert_eq!(
        vyrn_crypto::hash::hash(&rec).0.to_vec(),
        bytes(&g, "rec.blake3")
    );
    assert_eq!(decode_record(&rec).unwrap(), blk);
}

#[test]
fn reserved_tags_are_rejected() {
    let mut st = ref_state();
    for t in [0x45u8, 0x80, 0xFE] {
        assert_eq!(
            st.clone().decode_sections(&[t], BodyKind::Order),
            Err(RepErr::Tag)
        );
    }
    assert_eq!(
        st.decode_sections(&[0x44], BodyKind::Order),
        Err(RepErr::Tenure)
    );
}
