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
    PacketFlags, PacketRecord, PktHash, RouteRecord, SessionId, StepFlags, StepId, StepKind,
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
                snap_lag: 0,
            })],
        },
        Section::StepRun(vec![StepHalf {
            lowver: 0,
            step: StepId(1),
            kind: StepKind::Cross,
            other: false,
            home: Some(Home {
                src_lane: LaneId(7),
                src_lane_seq: LaneSeq(10),
                flags: 0,
                payload: vec![],
            }),
            cut,
        }]),
    ];
    let enc = st.encode_sections(&sections, BodyKind::Order).unwrap();
    assert_eq!(enc, bytes(&g, "ex311.sections"));
    assert_eq!(enc.len(), 21, "07 §3.11: 21 bytes");

    let mut dec = ref_state();
    dec.encode_sections(std::slice::from_ref(&bind), BodyKind::Order)
        .unwrap();
    assert_eq!(
        dec.decode_sections(&enc, BodyKind::Order).unwrap(),
        sections
    );

    // The step as an Improve that its lane classified Cross: StepRecord.flags CROSS rides in
    // bit 7 of the src byte, at no extra byte.
    let bound = || {
        let mut st = ref_state();
        st.encode_sections(std::slice::from_ref(&bind), BodyKind::Order)
            .unwrap();
        st
    };
    let mut cross = sections.clone();
    if let Section::StepRun(hs) = &mut cross[1] {
        hs[0].kind = StepKind::Improve;
        hs[0].home.as_mut().unwrap().flags = StepFlags::CROSS;
    }
    let enc = bound().encode_sections(&cross, BodyKind::Order).unwrap();
    assert_eq!(enc, bytes(&g, "ex311.cross_route.sections"));
    assert_eq!(enc.len(), 21);
    assert_eq!(
        bound().decode_sections(&enc, BodyKind::Order).unwrap(),
        cross
    );
    // The step took lane 7's lowver (07 §3.8 LOWVER): a second bitmap, 4 more bytes.
    let mut low = sections.clone();
    if let Section::StepRun(hs) = &mut low[1] {
        hs[0].lowver = 1 << 7;
    }
    let enc = bound().encode_sections(&low, BodyKind::Order).unwrap();
    assert_eq!(enc, bytes(&g, "ex311.lowver.sections"));
    assert_eq!(enc.len(), 25);
    assert_eq!(bound().decode_sections(&enc, BodyKind::Order).unwrap(), low);
    for bad in [
        "ex311.bad_lowver_empty.sections",
        "ex311.bad_lowver_unchanged.sections",
    ] {
        assert_eq!(
            bound().decode_sections(&bytes(&g, bad), BodyKind::Order),
            Err(RepErr::Cut),
            "{bad}"
        );
    }
    // An encoder refuses a lowver lane whose cut did not move.
    if let Section::StepRun(hs) = &mut low[1] {
        hs[0].lowver = 1 << 4;
    }
    assert_eq!(
        bound().encode_sections(&low, BodyKind::Order),
        Err(RepErr::Cut)
    );
    assert_eq!(
        bound().decode_sections(&bytes(&g, "ex311.bad_src_bit6.sections"), BodyKind::Order),
        Err(RepErr::Cut)
    );
    // snap_lag (05 §6.5) is LEB128 after the packet record's other fields; above u16::MAX is
    // REP_E_RANGE.
    let mut lagged = sections[..1].to_vec();
    if let Section::LaneRun { recs, .. } = &mut lagged[0]
        && let LaneRec::Pkt(p) = &mut recs[0]
    {
        p.snap_lag = 300;
    }
    let enc = bound().encode_sections(&lagged, BodyKind::Order).unwrap();
    assert_eq!(enc, bytes(&g, "ex311.snap_lag.sections"));
    assert_eq!(
        bound().decode_sections(&enc, BodyKind::Order).unwrap(),
        lagged
    );
    assert_eq!(
        bound().decode_sections(&bytes(&g, "ex311.bad_snap_lag.sections"), BodyKind::Order),
        Err(RepErr::Range)
    );
    // G9: a RouteRecord after the packet, 3 bytes; bad back and reserved bits are rejected.
    let pkt = sections[0].clone();
    let Section::LaneRun { recs, .. } = &pkt else {
        unreachable!()
    };
    let route = vec![Section::LaneRun {
        lane: LaneId(7),
        recs: vec![
            recs[0],
            LaneRec::Route(RouteRecord {
                lane: LaneId(7),
                lane_seq: LaneSeq(8),
                cross: true,
            }),
        ],
    }];
    let enc = bound().encode_sections(&route, BodyKind::Order).unwrap();
    assert_eq!(enc, bytes(&g, "ex311.route.sections"));
    assert_eq!(enc.len(), 11, "a RouteRecord costs 3 bytes");
    assert_eq!(
        bound().decode_sections(&enc, BodyKind::Order).unwrap(),
        route
    );
    for k in [
        "ex311.bad_route_back.sections",
        "ex311.bad_route_bits.sections",
    ] {
        assert_eq!(
            bound().decode_sections(&bytes(&g, k), BodyKind::Order),
            Err(RepErr::Count),
            "{k}"
        );
    }
    let mut beyond = route.clone();
    if let Section::LaneRun { recs, .. } = &mut beyond[0]
        && let LaneRec::Route(r) = &mut recs[1]
    {
        r.lane_seq = LaneSeq(11);
    }
    assert_eq!(
        bound().encode_sections(&beyond, BodyKind::Order),
        Err(RepErr::Count),
        "a RouteRecord names an op of the preceding packet"
    );
    // A MID Advance record (07 §3.6): MID in h bit 4, PASS2 in bit 7, then `back` as LEB128.
    for (k, flags, first) in [
        ("ex311.mid.sections", PacketFlags::MID, 8),
        (
            "ex311.mid_pass2.sections",
            PacketFlags::MID | PacketFlags::PASS2,
            8,
        ),
        ("ex311.mid_end.sections", PacketFlags::MID, 11),
    ] {
        let mid = vec![Section::LaneRun {
            lane: LaneId(7),
            recs: vec![
                recs[0],
                LaneRec::Pkt(PacketRecord {
                    lane: LaneId(7),
                    count: 0,
                    flags: PacketFlags::ADVANCE | flags,
                    session: SessionId(0),
                    pkt_seq: 0,
                    rx_ts: Nanos(1_000_512),
                    pkt_hash: PktHash(0),
                    first_lane_seq: LaneSeq(first),
                    fills_applied: StepId(1),
                    snap_lag: 0,
                }),
                // The lane's next LaneSeq stays 11: a route after the MID record still names
                // an op of the packet.
                LaneRec::Route(RouteRecord {
                    lane: LaneId(7),
                    lane_seq: LaneSeq(8),
                    cross: true,
                }),
            ],
        }];
        let mut want = bytes(&g, k);
        want[1] = 3;
        want.extend([0x82, 0x82, 0x20]);
        let enc = bound().encode_sections(&mid, BodyKind::Order).unwrap();
        assert_eq!(enc, want, "{k}");
        assert_eq!(
            bound().decode_sections(&enc, BodyKind::Order).unwrap(),
            mid,
            "{k}"
        );
    }
    for k in [
        "ex311.bad_mid_back.sections",
        "ex311.bad_mid_pass2.sections",
        "ex311.bad_mid_lseq.sections",
    ] {
        assert_eq!(
            bound().decode_sections(&bytes(&g, k), BodyKind::Order),
            Err(RepErr::Count),
            "{k}"
        );
    }
    // CROSS needs a source, and no other flag bit exists.
    for (src, flags) in [(0xFF, StepFlags::CROSS), (7, 1)] {
        let mut bad = cross.clone();
        if let Section::StepRun(hs) = &mut bad[1] {
            if src == 0xFF {
                hs[0].kind = StepKind::Idle;
            }
            let h = hs[0].home.as_mut().unwrap();
            if src == 0xFF {
                h.src_lane = LaneId(0xFF);
                h.src_lane_seq = LaneSeq(0);
            }
            h.flags = flags;
        }
        assert_eq!(
            bound().encode_sections(&bad, BodyKind::Order),
            Err(RepErr::Kind)
        );
    }
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
        snap_lag: 0,
    })
}

fn lagged(r: LaneRec, snap_lag: u16) -> LaneRec {
    match r {
        LaneRec::Pkt(p) => LaneRec::Pkt(PacketRecord { snap_lag, ..p }),
        x => x,
    }
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
                    lagged(pkt(0, 1, 0x0030_1007, 5, 1_000_600, 4, 0), 2),
                ],
            },
            Section::LaneRun {
                lane: LaneId(1),
                recs: vec![advance],
            },
            Section::StepRun(vec![
                StepHalf {
                    lowver: 0,
                    step: StepId(1),
                    kind: StepKind::Improve,
                    other: false,
                    home: Some(Home {
                        src_lane: LaneId(0),
                        src_lane_seq: LaneSeq(4),
                        flags: 0,
                        payload: vec![],
                    }),
                    cut: vec![LaneSeq(4), LaneSeq(0)],
                },
                StepHalf {
                    lowver: 0,
                    step: StepId(2),
                    kind: StepKind::Control,
                    other: true,
                    home: Some(Home {
                        src_lane: LaneId(0xFF),
                        src_lane_seq: LaneSeq(0),
                        flags: 0,
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
                lowver: 0,
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

fn ident(tenure: u8) -> Ident {
    Ident {
        book: BookId(1),
        epoch: Epoch(1000),
        tenure,
        sender: 0,
    }
}

#[test]
fn a_bad_frame_header_poisons_the_substream() {
    let g = golden();
    let a1 = bytes(&g, "blk.frame.a1");
    let mut dec = StreamDecoder::new(layout4(), 0).unwrap();
    let mut bad = a1.clone();
    bad[0] ^= 1;
    assert_eq!(dec.decode(&bad), Err(RepErr::Header));
    assert_eq!(dec.decode(&a1), Err(RepErr::Poisoned));
}

#[test]
fn a_new_tenure_keeps_the_epochs_session_slots() {
    let g = golden();
    let (a, _, _) = bodies(&g);
    let mut enc = StreamEncoder::new(layout4(), 0, ident(0)).unwrap();
    let mut dec = StreamDecoder::new(layout4(), 0).unwrap();
    for b in &a {
        dec.decode(&enc.encode(b).unwrap()).unwrap();
    }
    // Tenure 1 opens without a SessionBind; slot 5 still predicts pkt_seq 6.
    let mut ts = tenure_start();
    ts.tenure = 1;
    ts.first_step = StepId(3);
    ts.first_height = Height(101);
    let body = Body::Order {
        tenure_start: Some(ts),
        sections: vec![Section::LaneRun {
            lane: LaneId(0),
            recs: vec![pkt(0, 1, 0x0030_1007, 6, 1_000_100, 1, 0)],
        }],
    };
    assert_eq!(enc.next_tenure(ident(0)), Err(RepErr::Tenure));
    enc.next_tenure(ident(1)).unwrap();
    let f = enc.encode(&body).unwrap();
    // The record costs no SEQ_EXC: h = 01, slot 05, zigzag(+100) = c8 01, snap_lag 00.
    assert!(f.ends_with(&[0x00, 0x01, 0x01, 0x05, 0xc8, 0x01, 0x00]));
    let mut fresh = StreamDecoder::new(layout4(), 0).unwrap();
    assert_eq!(
        fresh.decode(&f),
        Err(RepErr::Range),
        "a fresh decoder has no slot 5"
    );
    dec.next_tenure().unwrap();
    assert_eq!(dec.decode(&f).unwrap().body, body);
    // An older tenure cannot follow.
    let mut back = dec.clone();
    back.next_tenure().unwrap();
    let mut old = StreamEncoder::new(layout4(), 0, ident(0)).unwrap();
    let f0 = old.encode(&a[0]).unwrap();
    assert_eq!(back.decode(&f0), Err(RepErr::Tenure));
}

#[test]
fn a_failed_encode_poisons_the_encoder() {
    let g = golden();
    let (a, _, _) = bodies(&g);
    let mut enc = StreamEncoder::new(layout4(), 0, ident(0)).unwrap();
    enc.encode(&a[0]).unwrap();
    // A Control step whose payload pushes the body past body_len's u16.
    let big = Body::Order {
        tenure_start: None,
        sections: vec![Section::StepRun(vec![StepHalf {
            lowver: 0,
            step: StepId(3),
            kind: StepKind::Control,
            other: false,
            home: Some(Home {
                src_lane: LaneId(0xFF),
                src_lane_seq: LaneSeq(0),
                flags: 0,
                payload: vec![0; 70_000],
            }),
            cut: vec![LaneSeq(4), LaneSeq(0)],
        }])],
    };
    assert_eq!(enc.encode(&big), Err(RepErr::Header));
    assert_eq!(enc.encode(&a[1]), Err(RepErr::Poisoned));
    assert_eq!(enc.next_tenure(ident(1)), Err(RepErr::Poisoned));
}

#[test]
fn next_tenure_compares_the_full_epoch() {
    let g = golden();
    let (a, _, _) = bodies(&g);
    let mut enc = StreamEncoder::new(layout4(), 0, ident(0)).unwrap();
    let mut dec = StreamDecoder::new(layout4(), 0).unwrap();
    dec.decode(&enc.encode(&a[0]).unwrap()).unwrap();
    dec.next_tenure().unwrap();
    // Epoch 1000 + 65536 has the same epoch16 (0x03e8) as epoch 1000.
    let far = Ident {
        epoch: Epoch(1000 + 65_536),
        tenure: 1,
        ..ident(1)
    };
    let mut ts = tenure_start();
    ts.epoch = far.epoch;
    ts.tenure = 1;
    let mut other = StreamEncoder::new(layout4(), 0, far).unwrap();
    let f = other
        .encode(&Body::Order {
            tenure_start: Some(ts),
            sections: vec![],
        })
        .unwrap();
    assert_eq!(f[6..8], 0x03e8u16.to_le_bytes(), "same epoch16 on the wire");
    assert_eq!(dec.decode(&f), Err(RepErr::Tenure));
}

#[test]
fn a_failed_frame_closes_no_block() {
    let g = golden();
    let (a, _, _) = bodies(&g);
    let mut enc = StreamEncoder::new(layout4(), 0, ident(0)).unwrap();
    // Frame 1 closes height 100 and is emitted.
    enc.encode(&a[0]).unwrap();
    // A mark for height 101, then padding past body_len's u16: the frame fails.
    let bad = Body::Order {
        tenure_start: None,
        sections: vec![
            Section::BlockMark(BlockMark {
                height: Height(101),
                last_step: StepId(2),
                lane_bounds: vec![LaneSeq(4), LaneSeq(0)],
            }),
            Section::Pad(70_000),
        ],
    };
    assert_eq!(enc.encode(&bad), Err(RepErr::Header));
    let closed = enc.take_closed();
    assert_eq!(
        closed.iter().map(|h| h.height).collect::<Vec<_>>(),
        vec![Height(100)]
    );
}
