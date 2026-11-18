//! Golden byte vectors (vectors/codec.txt): every case is encoded from its field values and
//! compared with the file's bytes, then the bytes are decoded back to the same value. The bytes
//! in the file were written by hand from the 05 §4.12/§4.15 and 01 §6.2/§6.4 tables.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeMap;

use vyrn_bbo::*;
use vyrn_types::*;

fn cases() -> BTreeMap<String, BTreeMap<String, String>> {
    let text = include_str!("../vectors/codec.txt");
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut cur = String::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let (k, v) = line.split_once(" = ").unwrap();
        if k == "case" {
            cur = v.to_string();
            assert!(
                out.insert(cur.clone(), BTreeMap::new()).is_none(),
                "duplicate case {v}"
            );
        } else {
            out.get_mut(&cur)
                .unwrap()
                .insert(k.to_string(), v.to_string());
        }
    }
    out
}

fn bytes(c: &BTreeMap<String, String>) -> Vec<u8> {
    let h = &c["bytes"];
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn num(c: &BTreeMap<String, String>, k: &str) -> u64 {
    u64::from_str_radix(c[k].trim_start_matches("0x"), 16).unwrap()
}

fn words<const W: usize>(b: &[u8]) -> [u64; W] {
    core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()))
}

fn fwd_case(c: &BTreeMap<String, String>) -> FwdEntry {
    let mut msg = [0u8; 16];
    for (i, m) in msg.iter_mut().enumerate() {
        *m = u8::from_str_radix(&c["msg"][2 * i..2 * i + 2], 16).unwrap();
    }
    let e = FwdEntry {
        lane_seq: LaneSeq(num(c, "lane_seq")),
        prio_ts: Nanos(num(c, "prio_ts")),
        snap_ver: num(c, "snap_ver") as u32,
        deadline: num(c, "deadline") as u32,
        msg,
        handle: Handle(num(c, "handle") as u32),
        vslot: num(c, "vslot") as u32,
        session: SessionId(num(c, "session") as u32),
        resp_seq: num(c, "resp_seq") as u32,
        pkt_seq: num(c, "pkt_seq") as u32,
        acct_ix: num(c, "acct_ix") as u16,
        applied_back: num(c, "applied_back") as u16,
    };
    assert_eq!(line_bytes(&e.encode()).to_vec(), bytes(c));
    assert_eq!(FwdEntry::decode(&words(&bytes(c))), e);
    e
}

#[test]
fn fwd_entry() {
    fwd_case(&cases()["fwd_entry"]);
}

#[test]
fn fwd_entry_cross_shares_byte_2_with_the_index() {
    let all = cases();
    let c = &all["fwd_entry_cross"];
    let e = fwd_case(c);
    assert_eq!(
        (e.index(), e.cross(), e.n_dep(), e.msg_type()),
        (
            num(c, "index") as u8,
            num(c, "cross") == 1,
            num(c, "n_dep") as u8,
            MSG_NEW
        )
    );
    let mut lines = [[0u64; 8]; 4];
    assert_eq!(encode_fwd(&e, &[FwdDep::default(); 2], &mut lines), 2);
    assert!(
        FwdEntry::decode(&lines[0]).cross(),
        "encode_fwd keeps the route bit"
    );
}

#[test]
fn fwd_dep_line() {
    let all = cases();
    let c = &all["fwd_dep_line"];
    let d0 = FwdDep {
        back: 1,
        kind: DEP_CANCEL,
        flags: OrderFlags(0x2d),
        pos: 15,
        tick: Tick(0x1112_1314),
        qty: Qty(0x2122_2324),
        slot: 0x3132_3334,
    };
    let d1 = FwdDep {
        back: 9,
        kind: DEP_JOIN,
        flags: OrderFlags(0),
        pos: 0,
        tick: Tick(0x4142_4344),
        qty: Qty(0x5152_5354),
        slot: 0x6162_6364,
    };
    assert_eq!(
        line_bytes(&FwdDep::encode_line(&[d0, d1])).to_vec(),
        bytes(c)
    );
    let back = FwdDep::decode_line(&words(&bytes(c)));
    assert_eq!(back[..2], [d0, d1]);
    assert_eq!(back[2], FwdDep::default());
    let f = d0.flags;
    assert_eq!(
        (f.side(), f.tif(), f.post_only(), f.stp()),
        (Side::Sell, Tif::Fok, true, Stp::CancelOldest)
    );
}

#[test]
fn fill_event() {
    let all = cases();
    let c = &all["fill_event"];
    let e = FillEvent {
        step: StepId(num(c, "step")),
        handle: Handle(num(c, "handle") as u32),
        vslot: num(c, "vslot") as u32,
        tick: Tick(num(c, "tick") as u32),
        qty: num(c, "qty") as u32,
        kind: num(c, "kind") as u8,
        liq: num(c, "liq") as u8,
        cause: num(c, "cause") as u16,
        ordinal: num(c, "ordinal") as u32,
    };
    assert_eq!(line32_bytes(&e.encode()).to_vec(), bytes(c));
    assert_eq!(FillEvent::decode(&words(&bytes(c))), e);
}

#[test]
fn step_entry_and_deltas() {
    let all = cases();
    let c = &all["step_entry"];
    let e = StepEntry {
        lowver: 0,
        step: StepId(num(c, "step")),
        kind: num(c, "kind") as u8,
        src_lane: LaneId(num(c, "src_lane") as u8),
        n_delta: num(c, "n_delta") as u8,
        n_tx: num(c, "n_tx") as u8,
        n_fills: num(c, "n_fills") as u32,
        src_lane_seq: LaneSeq(num(c, "src_lane_seq")),
        pub_a: num(c, "pub_a") as u32,
        pub_b: num(c, "pub_b") as u32,
        band_lo: Tick(num(c, "band_lo") as u32),
        band_hi: Tick(num(c, "band_hi") as u32),
        fill_lanes: num(c, "fill_lanes"),
        flags: num(c, "flags") as u8,
    };
    assert_eq!(line_bytes(&e.encode()).to_vec(), bytes(c));
    assert_eq!(StepEntry::decode(&words(&bytes(c))), e);
    assert_eq!((STEP_CONT, STEP_CROSS), (1, 2));
    assert_eq!(
        STEP_CROSS,
        StepFlags::CROSS,
        "StepRecord.flags uses StepEntry's bit"
    );
    let d = &all["cut_delta_line"];
    let ds = [
        CutDelta {
            lane: LaneId(5),
            seq: LaneSeq(0x1112_1314_1516_1718),
        },
        CutDelta {
            lane: LaneId(0x30),
            seq: LaneSeq(0x2122_2324_2526_2728),
        },
    ];
    assert_eq!(line_bytes(&CutDelta::encode_line(&ds)).to_vec(), bytes(d));
    assert_eq!(CutDelta::decode_line(&words(&bytes(d)))[..2], ds);
}

#[test]
fn tx_entry() {
    let all = cases();
    let c = &all["tx_entry"];
    let e = TxEntry {
        step: StepId(num(c, "step")),
        session: SessionId(num(c, "session") as u32),
        resp_seq: num(c, "resp_seq") as u32,
        pkt_seq: num(c, "pkt_seq") as u32,
        lane: LaneId(num(c, "lane") as u8),
        n_rec: num(c, "n_rec") as u8,
        role: num(c, "role") as u8,
    };
    assert_eq!(e.role, ROLE_MAKER);
    assert_eq!(line_bytes(&e.encode()).to_vec(), bytes(c));
    assert_eq!(TxEntry::decode(&words(&bytes(c))), e);
}

#[test]
fn records() {
    let all = cases();
    let (h, t) = (Handle(0x1112_1314), 0x3132_3334);
    let recs = [
        (
            "record_ack",
            Record::Ack {
                index: 3,
                handle: h,
                tick: Tick(0x2122_2324),
                client_tag: t,
            },
        ),
        (
            "record_fill",
            Record::Fill {
                index: INDEX_MAKER,
                liq: LIQ_MAKER,
                handle: h,
                tick: Tick(0x2122_2324),
                qty: Qty(t),
            },
        ),
        (
            "record_reject",
            Record::Reject {
                index: 2,
                reason: RejectReason::Busy,
                detail: 0x4142_4344,
                client_tag: 0x5152_5354,
            },
        ),
        (
            "record_cancel_ack",
            Record::CancelAck {
                index: 1,
                handle: h,
                canceled: Qty(0x2122_2324),
                client_tag: t,
            },
        ),
        (
            "record_out",
            Record::Out {
                index: 4,
                cause: OUT_STP,
                handle: h,
                qty: Qty(0x2122_2324),
                client_tag: t,
            },
        ),
    ];
    for (name, r) in recs {
        let b = bytes(&all[name]);
        assert_eq!(r.encode().to_vec(), b, "{name}");
        assert_eq!(
            Record::decode(&b.clone().try_into().unwrap()),
            Some(r),
            "{name}"
        );
    }
    let mut line = [0u8; 64];
    for (i, (name, _)) in recs.iter().take(4).enumerate() {
        line[16 * i..16 * i + 16].copy_from_slice(&bytes(&all[*name]));
    }
    let packed = encode_records(&recs.iter().take(4).map(|r| r.1).collect::<Vec<_>>());
    assert_eq!(line_bytes(&packed), line, "4 records per line, in order");
}

#[test]
fn order_flags_and_rank_e() {
    let all = cases();
    let f = OrderFlags::new(Side::Sell, Tif::Fok, true, Stp::CancelBoth);
    assert_eq!(vec![f.0], bytes(&all["order_flags"]));
    let c = &all["rank_e"];
    assert_eq!(
        u64::from(rank_e(Epoch(0x32), LaneId(3), 0x31)),
        num(c, "rank")
    );
    assert_eq!(
        u64::from(rank_e(Epoch(u32::MAX), LaneId(0x30), 0x31)),
        num(c, "rank2")
    );
}
