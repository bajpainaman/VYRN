//! Golden vectors from tests/golden (spec/11-build.md §6.1). Each file comes from an upstream
//! source, so these tests check the implementation against values it did not produce.

use core::hash::Hasher;
use vyrn_crypto::siphash::{SipHasher24, siphash24, verify};
use vyrn_crypto::{ed25519, hash, x25519};
use vyrn_types::Tag;

macro_rules! golden {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/golden/",
            $name
        ))
    };
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().unwrap()
}

fn data_lines(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_whitespace().collect())
}

const SIP_KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[test]
fn siphash_paper_vectors() {
    let mut n = 0;
    for f in data_lines(golden!("siphash.txt")) {
        let len: usize = f[0].parse().unwrap();
        let want = Tag(u64::from_le_bytes(arr(f[1])));
        let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
        assert_eq!(siphash24(&SIP_KEY, &msg), want, "one-shot, len {len}");
        assert!(verify(&SIP_KEY, &msg, want));

        // The streaming hasher must buffer across every split point.
        for split in 0..=len {
            let mut h = SipHasher24::new(&SIP_KEY);
            h.write(&msg[..split]);
            h.write(&msg[split..]);
            assert_eq!(h.finish(), want.0, "streaming, len {len}, split {split}");
        }
        n += 1;
    }
    assert_eq!(n, 64);
    // 04 §11 quotes this one directly.
    assert_eq!(
        siphash24(&SIP_KEY, &unhex("000102030405060708090a0b0c0d0e")).0,
        0xa129ca6149be45e5
    );
}

/// Pulls `"field": "value"` (or a number) out of one case object of the BLAKE3 JSON.
fn field<'a>(case: &'a str, name: &str) -> &'a str {
    let at = case.find(&format!("\"{name}\":")).unwrap() + name.len() + 3;
    let rest = case[at..].trim_start();
    if let Some(s) = rest.strip_prefix('"') {
        &s[..s.find('"').unwrap()]
    } else {
        &rest[..rest.find(|c: char| !c.is_ascii_digit()).unwrap()]
    }
}

#[test]
fn blake3_official_vectors() {
    let json = golden!("blake3_test_vectors.json");
    let key: [u8; 32] = field(json, "key").as_bytes().try_into().unwrap();
    let context = field(json, "context_string");
    let cases: Vec<&str> = json.split("\"input_len\"").skip(1).collect();
    assert_eq!(cases.len(), 35);
    for c in cases {
        let c = format!("\"input_len\"{c}");
        let len: usize = field(&c, "input_len").parse().unwrap();
        let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        // The vectors give 131 bytes of extended output; the first 32 are BLAKE3-256.
        let prefix = |name| arr::<32>(&field(&c, name)[..64]);
        assert_eq!(hash::hash(&input).0, prefix("hash"), "hash, len {len}");
        assert_eq!(
            hash::keyed_hash(&key, &input).0,
            prefix("keyed_hash"),
            "keyed, len {len}"
        );
        assert_eq!(
            hash::derive_key(context, &input),
            prefix("derive_key"),
            "derive_key, len {len}"
        );
    }
}

#[test]
fn ed25519_zip215_edge_cases() {
    let mut n = 0;
    for f in data_lines(golden!("ed25519-edge.txt")) {
        let want = match f[1] {
            "V" => true,
            "X" => false,
            v => panic!("bad verdict {v}"),
        };
        let got = ed25519::verify(&arr(f[3]), &unhex(f[2]), &arr(f[4]));
        assert_eq!(got, want, "case {}", f[0]);
        n += 1;
    }
    assert_eq!(n, 12);
}

#[test]
fn ed25519_rfc8032_test_1() {
    let seed = arr("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk = arr("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let sig: [u8; 64] = arr(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    assert_eq!(ed25519::public_key(&seed), pk);
    assert_eq!(ed25519::sign(&seed, b""), sig);
    assert!(ed25519::verify(&pk, b"", &sig));
    assert!(!ed25519::verify(&pk, b"x", &sig));
    for byte in [0, 31, 32, 63] {
        let mut bad = sig;
        bad[byte] ^= 1;
        assert!(!ed25519::verify(&pk, b"", &bad), "flipped byte {byte}");
    }
}

#[test]
fn x25519_rfc7748_section_6_1() {
    let a = arr("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let b = arr("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let a_pub = arr("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let b_pub = arr("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = arr("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(x25519::public_key(&a), a_pub);
    assert_eq!(x25519::public_key(&b), b_pub);
    assert_eq!(x25519::shared_secret(&a, &b_pub), Some(shared));
    assert_eq!(x25519::shared_secret(&b, &a_pub), Some(shared));
    // The identity point is low order: no contributory secret.
    assert_eq!(x25519::shared_secret(&a, &[0; 32]), None);
}
