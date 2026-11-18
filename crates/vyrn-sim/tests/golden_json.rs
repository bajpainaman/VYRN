//! Reads the JSON form of the golden vectors (`tests/golden/*_vectors.json`, README "JSON form")
//! and checks it against the real codecs: `vyrn-wire` for the proto, reject and session records,
//! `vyrn-lane` for the session-state details. The `.out` files have their own tests; this one makes
//! sure the JSON is consumed, not only generated.
//!
//! The JSON reader is `vyrn-lane`'s test module (`tests/json`), shared so both crates read the
//! files the same way.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use vyrn_types::RejectReason;
use vyrn_wire::{Record, Request, Response};

const K_SEQ: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const K_OUT: [u8; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const K_COM: [u8; 16] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
];

#[path = "../../engine/vyrn-lane/tests/json/mod.rs"]
mod json;

use json::{J, unhex};

fn load(name: &str) -> J {
    json::load(env!("CARGO_MANIFEST_DIR"), name)
}

fn tag(t: &J, k: &str) -> u64 {
    u64::from_str_radix(t.s(k).trim_start_matches("0x"), 16).unwrap()
}

/// 04 §11: every request parses, verifies under `K_seq` (and `K_com` when it carries one) and
/// decodes every message; every response parses, verifies under `K_out` and decodes every
/// record. The JSON `tags` are the packet's trailing tags.
#[test]
fn proto_json_vectors_parse_and_verify() {
    let doc = load("vyrn_proto_vectors.json");
    let (mut reqs, mut resps) = (0, 0);
    for v in doc.arr("vectors") {
        let (id, b) = (v.s("id"), unhex(v.s("hex")));
        match v.s("tagging") {
            "request" => {
                let p = Request::parse(&b).unwrap_or_else(|e| panic!("{id}: {e:?}"));
                assert!(p.verify_seq(&K_SEQ), "{id} tag_seq");
                let t = v.at("tags");
                let n = b.len();
                assert_eq!(tag(t, "tag_seq").to_le_bytes(), b[n - 16..n - 8], "{id}");
                assert_eq!(tag(t, "tag_com").to_le_bytes(), b[n - 8..], "{id}");
                if tag(t, "tag_com") != 0 {
                    assert!(p.verify_com(&K_COM), "{id} tag_com");
                }
                assert!(p.msgs().all(|m| m.is_ok()), "{id} messages");
                reqs += 1;
            }
            // V19 is a data-tier `DataRedirect` (04 §7.6); vyrn-data checks it.
            "single" if id == "V19" => {}
            "single" => {
                let p = Response::parse(&b).unwrap_or_else(|e| panic!("{id}: {e:?}"));
                assert!(p.verify(&K_OUT), "{id} tag");
                assert_eq!(
                    tag(v.at("tags"), "tag").to_le_bytes(),
                    b[b.len() - 8..],
                    "{id}"
                );
                assert!(p.records().all(|r| r.is_ok()), "{id} records");
                resps += 1;
            }
            // V20, an admin frame: vyrn-admin's codec checks it.
            "none" => {}
            t => panic!("{id}: tagging {t}"),
        }
    }
    assert_eq!((reqs, resps), (10, 10));
}

/// The reject vectors through `vyrn-wire`: each verdict of the JSON, as `vectors.rs` checks the
/// `.out` form.
#[test]
fn reject_json_vectors_get_their_verdicts() {
    let doc = load("vyrn_reject_vectors.json");
    let verdict = |e: vyrn_wire::WireError| format!("{}/{}", e.reason.code(), e.detail);
    let vs = doc.arr("vectors");
    for v in vs {
        let (id, b) = (v.s("id"), unhex(v.s("hex")));
        let want: Option<Vec<&str>> =
            (v.s("verdict") != "drop").then(|| v.arr("results").iter().map(J::as_str).collect());
        let got: Option<Vec<String>> = if v.s("dir") == "req" {
            Request::parse(&b).ok().map(|p| {
                assert!(p.verify_seq(&K_SEQ), "{id} tag_seq");
                let hdr = p.check_header().err();
                p.msgs()
                    .map(|m| match (hdr, m) {
                        (Some(e), _) | (None, Err(e)) => verdict(e),
                        (None, Ok(_)) => "ok".to_owned(),
                    })
                    .collect()
            })
        } else {
            Response::parse(&b).ok().map(|p| {
                assert!(p.verify(&K_OUT), "{id} tag");
                p.records()
                    .map(|r| match r {
                        Ok(Record::Reject { reason, detail, .. }) => {
                            format!("{}/{detail}", reason.code())
                        }
                        Ok(_) => "ok".to_owned(),
                        Err(_) => "bad".to_owned(),
                    })
                    .collect()
            })
        };
        let got: Option<Vec<&str>> = got.as_ref().map(|g| g.iter().map(String::as_str).collect());
        assert_eq!(got, want, "{id}");
    }
    assert_eq!(vs.len(), 49);
}

fn reason(name: &str) -> RejectReason {
    match name {
        "SESSION_CLOSED" => RejectReason::SessionClosed,
        "BAD_MAC" => RejectReason::BadMac,
        n => panic!("reason {n}"),
    }
}

/// 04 §4.3: each close cause's final record decodes with `vyrn-wire` to `Reject` at index 0xFF
/// with the cause as detail (`BAD_MAC`: the offending `pkt_seq`, 42); the `DRAINING` and
/// `CLOSED` details are the lane's.
#[test]
fn session_json_vectors_match_the_codec_and_the_lane() {
    let doc = load("vyrn_session_vectors.json");
    // 04 §4.3 close causes (`PROTO_D_*`).
    let causes = [
        ("LOGOUT", 1),
        ("BAD_MAC", 2),
        ("EQUIVOCATION", 3),
        ("ADMIN_KILL", 4),
        ("LANE_MOVED", 5),
        ("BOND", 6),
    ];
    let close = doc.arr("close");
    assert_eq!(close.len(), causes.len());
    for (c, (name, value)) in close.iter().zip(causes) {
        assert_eq!(c.s("cause"), name);
        let b: [u8; 16] = unhex(c.s("hex")).try_into().unwrap();
        let Ok(Record::Reject {
            index,
            reason: r,
            detail,
            ..
        }) = Record::decode(&b)
        else {
            panic!("{name}: not a Reject");
        };
        let want = if name == "BAD_MAC" {
            (RejectReason::BadMac, 42)
        } else {
            (RejectReason::SessionClosed, value)
        };
        assert_eq!((index, r, detail), (0xFF, want.0, want.1), "{name}");
    }
    let closed_cause = u32::try_from(doc.n("closed_cause")).unwrap();
    let mut seen = [0usize; 2];
    for s in doc.arr("states") {
        let (id, verdict) = (s.s("id"), s.s("verdict"));
        let detail = || u32::try_from(s.n("detail")).unwrap();
        match verdict {
            "reject" => {
                assert_eq!(s.s("state"), "DRAINING", "{id}");
                assert_eq!(reason(s.s("reason")), RejectReason::SessionClosed, "{id}");
                assert_eq!(detail(), vyrn_lane::lane::PROTO_D_DRAINING, "{id}");
                seen[0] += 1;
            }
            "oos" => {
                assert_eq!(s.s("state"), "CLOSED", "{id}");
                assert_eq!(reason(s.s("reason")), RejectReason::SessionClosed, "{id}");
                assert_eq!(detail(), closed_cause, "{id}");
                seen[1] += 1;
            }
            "accept" | "drop" => assert!(s.get("reason").is_none(), "{id}"),
            v => panic!("{id}: verdict {v}"),
        }
    }
    assert_eq!(seen, [2, 7]);
}
