//! The 04 §11 protocol conformance vectors. `tests/golden/vyrn_proto_vectors.out` is the output of
//! `python3 -I vyrn_proto_vectors.py`; this test builds the same 20 packets with `vyrn-wire`,
//! compares them byte for byte, parses each back, and repeats the script's checks.

use std::collections::BTreeMap;

use vyrn_types::{
    BookId, Epoch, Handle, LaneId, MAX_REQ_PAYLOAD, Qty, RejectReason, SessionId, Tick,
};
use vyrn_wire::{
    Liq, Msg, OrderFlags, OutCause, PROTO_HANDLE_ALL, PROTO_RESP_MAX_BYTES, Record, ReqHeader,
    Request, RespHeader, Response, Side, Stp, Tif, encode_request, encode_response, session_id,
};

const K_SEQ: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const K_OUT: [u8; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const K_COM: [u8; 16] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
];
const E: u32 = 1000;
const E16: u16 = 0x03e8;
const BOOK: BookId = BookId(1);

/// Vector name ("V1" … "V20") → bytes, from the script's hex dump.
fn golden() -> BTreeMap<String, Vec<u8>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/golden/vyrn_proto_vectors.out"
    );
    let text = std::fs::read_to_string(path).expect("golden vectors");
    let mut out = BTreeMap::new();
    let mut lens = BTreeMap::new();
    let mut cur = String::new();
    for line in text.lines() {
        if line.starts_with('V') {
            cur = line.split_whitespace().next().unwrap().to_owned();
            let len: usize = line
                .rsplit_once('(')
                .unwrap()
                .1
                .trim_end_matches(" B)")
                .parse()
                .unwrap();
            lens.insert(cur.clone(), len);
            out.insert(cur.clone(), Vec::new());
        } else if let (Some(bytes), Some((_, hex))) = (
            out.get_mut(&cur),
            line.strip_prefix("  ").and_then(|l| l.split_once(": ")),
        ) {
            bytes.extend(hex.split(' ').map(|h| u8::from_str_radix(h, 16).unwrap()));
        }
    }
    for (name, len) in &lens {
        assert_eq!(out[name].len(), *len, "{name} length in the dump");
    }
    assert_eq!(out.len(), 20);
    out
}

fn sid(slot: u16, lane: u8, generation: u16) -> SessionId {
    session_id(slot, LaneId(lane), generation).unwrap()
}

fn h(slot: u32, generation: u8) -> Handle {
    Handle::new(slot, generation).unwrap()
}

fn of(side: Side, tif: Tif, post_only: bool, stp: Stp) -> OrderFlags {
    OrderFlags {
        side,
        tif,
        post_only,
        stp,
    }
}

fn req(s: SessionId, seq: u32, msgs: &[Msg], k_com: Option<&[u8; 16]>, resend: bool) -> Vec<u8> {
    let mut buf = [0u8; MAX_REQ_PAYLOAD];
    let n = encode_request(
        &mut buf,
        ReqHeader::new(s, seq, E16, BOOK, resend),
        msgs,
        &K_SEQ,
        k_com,
    )
    .unwrap();
    buf[..n].to_vec()
}

fn resp(s: SessionId, rseq: u32, echo: u32, recs: &[Record], resend: bool) -> Vec<u8> {
    let mut buf = [0u8; PROTO_RESP_MAX_BYTES];
    let n = encode_response(
        &mut buf,
        RespHeader::new(s, rseq, E16, echo, resend),
        recs,
        &K_OUT,
    )
    .unwrap();
    buf[..n].to_vec()
}

enum Pkt {
    Req(Vec<Msg>, Vec<u8>),
    Resp(Vec<Record>, Vec<u8>),
}

/// The scenario of 04 §11, in the script's order.
fn built() -> Vec<(&'static str, Pkt)> {
    let (a, b, c) = (sid(7, 3, 1), sid(9, 5, 1), sid(2, 0, 4));
    let (a1, a2, a3, a4, b1) = (h(42, 1), h(43, 1), h(44, 1), h(45, 1), h(7, 3));
    let buy_stp = of(Side::Buy, Tif::Day, false, Stp::CancelNewest);
    let r = |m: Vec<Msg>, s, seq, com, resend| {
        let bytes = req(s, seq, &m, com, resend);
        Pkt::Req(m, bytes)
    };
    let p = |rs: Vec<Record>, s, rseq, echo, resend| {
        let bytes = resp(s, rseq, echo, &rs, resend);
        Pkt::Resp(rs, bytes)
    };
    let ack_a1 = Record::Ack {
        index: 0,
        handle: a1,
        tick: Tick(100_000),
        client_tag: 0x1111_1111,
    };
    // A lane-shed BUSY (04 §3.5): in stream, at the message's index, detail = the session's
    // `expected` (≥ 1; a BBO shed has 0), client_tag 0.
    let busy = |index, expected| Record::Reject {
        index,
        reason: RejectReason::Busy,
        detail: expected,
        client_tag: 0,
    };
    let ioc_buy = Msg::New {
        flags: of(Side::Buy, Tif::Ioc, false, Stp::None),
        tick: Tick(100_000),
        qty: Qty(2),
        client_tag: 0x8888_8888,
    };
    vec![
        (
            "V1",
            r(
                vec![Msg::New {
                    flags: buy_stp,
                    tick: Tick(100_000),
                    qty: Qty(5),
                    client_tag: 0x1111_1111,
                }],
                a,
                1,
                None,
                false,
            ),
        ),
        ("V2", p(vec![ack_a1], a, 1, 1, false)),
        (
            "V3",
            r(
                vec![
                    Msg::Cancel {
                        handle: a1,
                        client_tag: 0x2222_2222,
                    },
                    Msg::Reduce {
                        handle: a2,
                        by: Qty(2),
                        client_tag: 0x3333_3333,
                    },
                    Msg::Replace {
                        flags: buy_stp,
                        handle: a3,
                        tick: Tick(100_001),
                        qty: Qty(8),
                    },
                ],
                a,
                2,
                None,
                false,
            ),
        ),
        (
            "V4",
            p(
                vec![
                    Record::CancelAck {
                        index: 0,
                        handle: a1,
                        qty: Qty(5),
                        client_tag: 0x2222_2222,
                    },
                    Record::CancelAck {
                        index: 1,
                        handle: a2,
                        qty: Qty(2),
                        client_tag: 0x3333_3333,
                    },
                    Record::CancelAck {
                        index: 2,
                        handle: a3,
                        qty: Qty(4),
                        client_tag: 0x4444_4444,
                    },
                    Record::Ack {
                        index: 2,
                        handle: a4,
                        tick: Tick(100_001),
                        client_tag: 0x4444_4444,
                    },
                ],
                a,
                2,
                2,
                false,
            ),
        ),
        (
            "V5",
            r(
                vec![Msg::New {
                    flags: of(Side::Sell, Tif::Ioc, false, Stp::None),
                    tick: Tick(100_000),
                    qty: Qty(10),
                    client_tag: 0x5555_5555,
                }],
                b,
                1,
                None,
                false,
            ),
        ),
        (
            "V6",
            p(
                vec![
                    Record::Fill {
                        index: 0,
                        liq: Liq::Taker,
                        handle: b1,
                        tick: Tick(100_001),
                        qty: Qty(8),
                    },
                    Record::Fill {
                        index: 0,
                        liq: Liq::Taker,
                        handle: b1,
                        tick: Tick(100_000),
                        qty: Qty(1),
                    },
                    Record::Out {
                        index: 0,
                        cause: OutCause::IocRemainder,
                        handle: b1,
                        qty: Qty(1),
                        client_tag: 0x5555_5555,
                    },
                ],
                b,
                1,
                1,
                false,
            ),
        ),
        (
            "V7",
            p(
                vec![Record::Fill {
                    index: 0xFF,
                    liq: Liq::Maker,
                    handle: a4,
                    tick: Tick(100_001),
                    qty: Qty(8),
                }],
                a,
                3,
                0,
                false,
            ),
        ),
        ("V8", r(vec![Msg::Heartbeat], a, 3, None, false)),
        (
            "V9",
            p(
                vec![Record::EpochNotice {
                    next: Epoch(E + 1),
                    home: 2 | 1 << 8,
                    secs: 3600,
                }],
                a,
                4,
                3,
                false,
            ),
        ),
        (
            "V10",
            r(
                vec![Msg::New {
                    flags: of(Side::Sell, Tif::Day, true, Stp::None),
                    tick: Tick(100_002),
                    qty: Qty(3),
                    client_tag: 0x6666_6666,
                }],
                c,
                1,
                Some(&K_COM),
                false,
            ),
        ),
        (
            "V11",
            p(
                vec![Record::Reject {
                    index: 0xFF,
                    reason: RejectReason::EpochMismatch,
                    detail: E,
                    client_tag: 0,
                }],
                a,
                0,
                4,
                false,
            ),
        ),
        (
            "V12",
            r(vec![Msg::ResendReq { from: 1, to: 1 }], a, 4, None, false),
        ),
        ("V13", p(vec![ack_a1], a, 1, 1, true)),
        (
            "V14",
            r(
                vec![Msg::CancelAll {
                    client_tag: 0x7777_7777,
                }],
                a,
                5,
                None,
                false,
            ),
        ),
        (
            "V15",
            p(
                vec![
                    Record::CancelAck {
                        index: 0,
                        handle: a2,
                        qty: Qty(3),
                        client_tag: 0x7777_7777,
                    },
                    Record::CancelAck {
                        index: 0,
                        handle: h(46, 1),
                        qty: Qty(6),
                        client_tag: 0x7777_7777,
                    },
                    Record::CancelAck {
                        index: 0,
                        handle: Handle(PROTO_HANDLE_ALL),
                        qty: Qty(2),
                        client_tag: 0x7777_7777,
                    },
                ],
                a,
                6,
                5,
                false,
            ),
        ),
        ("V16", r(vec![ioc_buy], a, 6, None, false)),
        ("V17", p(vec![busy(0, 6)], a, 7, 6, false)),
        ("V18", r(vec![ioc_buy], a, 6, None, true)),
        (
            "V19",
            r(
                vec![
                    Msg::New {
                        flags: of(Side::Sell, Tif::Day, false, Stp::None),
                        tick: Tick(100_005),
                        qty: Qty(1),
                        client_tag: 0x9999_9999,
                    },
                    Msg::Heartbeat,
                ],
                a,
                7,
                None,
                false,
            ),
        ),
        ("V20", p(vec![busy(0, 7), busy(1, 7)], a, 9, 7, false)),
    ]
}

#[test]
fn every_vector_builds_byte_for_byte_and_parses_back() {
    let golden = golden();
    let built = built();
    assert_eq!(built.len(), golden.len());
    for (name, pkt) in &built {
        match pkt {
            Pkt::Req(msgs, bytes) => {
                assert_eq!(bytes, &golden[*name], "{name} bytes");
                let p = Request::parse(bytes).unwrap();
                p.check_header().unwrap();
                assert!(p.verify_seq(&K_SEQ), "{name} tag_seq");
                assert_eq!(
                    p.msgs().collect::<Result<Vec<_>, _>>().unwrap(),
                    *msgs,
                    "{name} messages"
                );
            }
            Pkt::Resp(recs, bytes) => {
                assert_eq!(bytes, &golden[*name], "{name} bytes");
                let p = Response::parse(bytes).unwrap();
                assert!(p.verify(&K_OUT), "{name} tag");
                assert_eq!(
                    p.records().collect::<Result<Vec<_>, _>>().unwrap(),
                    *recs,
                    "{name} records"
                );
            }
        }
    }
}

#[test]
fn the_scripts_checks_hold() {
    let g = golden();
    let v1 = Request::parse(&g["V1"]).unwrap();
    assert!(v1.verify_seq(&K_SEQ));
    assert!(!v1.verify_seq(&K_OUT));
    assert_eq!(v1.tag_com().0, 0, "BASE mode");

    let mut bad = g["V1"].clone();
    bad[32] ^= 0x01;
    assert!(
        !Request::parse(&bad).unwrap().verify_seq(&K_SEQ),
        "one tag bit flipped"
    );

    let v10 = Request::parse(&g["V10"]).unwrap();
    assert!(v10.verify_seq(&K_SEQ) && v10.verify_com(&K_COM) && !v10.verify_com(&K_SEQ));

    let (v2, v13) = (
        Response::parse(&g["V2"]).unwrap(),
        Response::parse(&g["V13"]).unwrap(),
    );
    assert!(v13.is_resend() && !v2.is_resend());
    assert_eq!(v2.header().resp_seq, v13.header().resp_seq);
    assert_ne!(v2.tag(), v13.tag());

    // A lane BUSY is in stream: it takes the next resp_seq (7 after V15's 6) and echoes the
    // shed pkt_seq; V20 runs one BUSY per message of V19, its Heartbeat included.
    let v17 = Response::parse(&g["V17"]).unwrap();
    assert!(!v17.is_out_of_stream());
    assert_eq!(
        (v17.header().resp_seq.get(), v17.header().echo_pkt.get()),
        (7, 6)
    );
    let v20 = Response::parse(&g["V20"]).unwrap();
    assert_eq!(
        (v20.header().resp_seq.get(), v20.header().echo_pkt.get()),
        (9, 7)
    );
    assert_eq!(
        v20.records().collect::<Result<Vec<_>, _>>().unwrap().len(),
        usize::from(Request::parse(&g["V19"]).unwrap().header().count)
    );

    let (v16, v18) = (
        Request::parse(&g["V16"]).unwrap(),
        Request::parse(&g["V18"]).unwrap(),
    );
    assert!(v18.is_resend() && !v16.is_resend());
    assert_eq!(v16.raw_msgs(), v18.raw_msgs());
    assert_eq!(v16.header().pkt_seq, v18.header().pkt_seq);
    assert!(v18.verify_seq(&K_SEQ));
}

/// `tests/golden/vyrn_reject_vectors.out`: validly tagged packets whose layout a v1 codec must
/// refuse (04 §3.1 V1 and V9, §3.3 M2 and M3, §12 VR1 and VR3), each with its expected verdict,
/// and Reject records it must decode to their reason and detail (the `RATE_LIMIT` ids of 04 §9.1).
#[test]
fn reject_vectors_get_their_verdicts() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/golden/vyrn_reject_vectors.out"
    );
    let text = std::fs::read_to_string(path).expect("reject vectors");
    let verdict = |e: vyrn_wire::WireError| format!("{}/{}", e.reason.code(), e.detail);
    let mut n = 0;
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (id, dir, want, hex) = match f[..] {
            [id, dir, "drop", hex] => (id, dir, None, hex),
            [id, dir, _, list, hex] => (id, dir, Some(list), hex),
            _ => panic!("bad line: {line}"),
        };
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let got = if dir == "req" {
            Request::parse(&bytes).ok().map(|p| {
                assert!(p.verify_seq(&K_SEQ), "{id} tag_seq");
                let hdr = p.check_header().err();
                p.msgs()
                    .map(|m| match (hdr, m) {
                        (Some(e), _) | (None, Err(e)) => verdict(e),
                        (None, Ok(_)) => "ok".to_owned(),
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
        } else {
            Response::parse(&bytes).ok().map(|p| {
                assert!(p.verify(&K_OUT), "{id} tag");
                p.records()
                    .map(|r| match r {
                        Ok(Record::Reject { reason, detail, .. }) => {
                            format!("{}/{detail}", reason.code())
                        }
                        Ok(_) => "ok".to_owned(),
                        Err(_) => "bad".to_owned(),
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
        };
        assert_eq!(got.as_deref(), want, "{id}");
        n += 1;
    }
    assert_eq!(n, 49);
}
