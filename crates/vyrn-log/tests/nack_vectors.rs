//! Checks `vyrn_log::nack` against `tests/golden/vyrn_nack_vectors.out`, which
//! `vyrn_nack_vectors.py` wrote from 07 §4.10 with no Rust involved: every `ok` vector decodes
//! and re-encodes to the same bytes, and every `refuse` vector decodes as neither message.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use vyrn_log::nack::{Nack, NackTooOld, Path};

const OUT: &str = include_str!("../../../tests/golden/vyrn_nack_vectors.out");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[path = "../../engine/vyrn-lane/tests/json/mod.rs"]
mod json;

/// The JSON form (`vyrn_nack_vectors.json`, README "JSON form") read through the shared reader
/// carries the `.out` vectors exactly, so every check here holds for it too.
#[test]
fn the_json_form_is_the_out_form() {
    let doc = json::load(env!("CARGO_MANIFEST_DIR"), "vyrn_nack_vectors.json");
    let got: Vec<String> = doc
        .arr("vectors")
        .iter()
        .map(|v| {
            let f = ["id", "message", "verdict", "hex"].map(|k| v.s(k));
            f.join(" ")
        })
        .collect();
    let want: Vec<&str> = OUT.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(got, want);
}

#[test]
fn nack_vectors() {
    let mut seen = 0;
    for l in OUT.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = l.split(' ').collect();
        let [id, msg, verdict, hex] = f[..] else {
            panic!("bad line {l}");
        };
        let b = unhex(hex);
        let (n, t) = (Nack::decode(&b), NackTooOld::decode(&b));
        match (msg, verdict) {
            ("Nack", "ok") => assert_eq!(n.unwrap().encode().to_vec(), b, "{id}"),
            ("NackTooOld", "ok") => assert_eq!(t.unwrap().encode().to_vec(), b, "{id}"),
            (_, "refuse") => assert!(n.is_none() && t.is_none(), "{id} must be refused"),
            _ => panic!("bad line {l}"),
        }
        seen += 1;
    }
    assert_eq!(seen, 15);
    // N02's fields, from the script's comment.
    let n02 = Nack {
        path: Path::B,
        epoch16: 0xBEEF,
        tenure: 3,
        stream: 1,
        port: 40001,
        from_seq: 1 << 40,
        to_seq: 1 << 40,
    };
    assert!(OUT.contains(&format!("N02 Nack ok {}", hex(&n02.encode()))));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
