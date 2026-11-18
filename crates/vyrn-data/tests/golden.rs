//! Checks `frame` and `dedupe` against `tests/golden/vyrn_data_vectors.out`, which an
//! independent Python script wrote byte by byte from the crate's documented layouts.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use vyrn_data::dedupe::{Dedupe, Seen};
use vyrn_data::frame::{self, DataHdr, Fetch, FrameBuf, Kind};
use vyrn_types::{BookId, Height, SessionId};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn lines() -> Vec<Vec<String>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/vyrn_data_vectors.out"
    );
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#') && l.contains(' '))
        .map(|l| l.split(' ').map(str::to_owned).collect())
        .collect()
}

fn kind(k: &str) -> Kind {
    match k {
        "1" => Kind::Data,
        "2" => Kind::DataHb,
        "3" => Kind::FetchResp,
        _ => panic!("kind {k}"),
    }
}

#[test]
fn data_frames_match_the_published_vectors() {
    let (mut ok, mut err) = (0, 0);
    for f in lines() {
        match f[0].as_str() {
            "data_ok" => {
                let pkts: Vec<Vec<u8>> = if f[7] == "-" {
                    vec![]
                } else {
                    f[7].split(',').map(unhex).collect()
                };
                let hdr = DataHdr {
                    kind: kind(&f[2]),
                    book: BookId(f[3].parse().unwrap()),
                    epoch16: f[4].parse().unwrap(),
                    data_seq: f[5].parse().unwrap(),
                    src: f[6].parse().unwrap(),
                };
                let want = unhex(&f[8]);
                // Encode.
                let mut b = FrameBuf::default();
                for p in &pkts {
                    assert!(b.push(p), "{}", f[1]);
                }
                assert_eq!(b.finish(&hdr), &want[..], "encode {}", f[1]);
                // Decode.
                let d = frame::decode(&want).unwrap();
                assert_eq!(d.hdr, hdr, "{}", f[1]);
                let got: Vec<&[u8]> = d.packets().collect();
                let want_p: Vec<&[u8]> = pkts.iter().map(Vec::as_slice).collect();
                assert_eq!(got, want_p, "{}", f[1]);
                ok += 1;
            }
            "data_err" => {
                let e = frame::decode(&unhex(&f[2])).unwrap_err();
                assert_eq!(format!("{e:?}"), f[3], "{}", f[1]);
                err += 1;
            }
            _ => {}
        }
    }
    assert_eq!((ok, err), (5, 13));
}

#[test]
fn fetches_match_the_published_vectors() {
    let (mut ok, mut err) = (0, 0);
    for f in lines() {
        match f[0].as_str() {
            "fetch_ok" => {
                let n = |i: usize| f[i].parse::<u64>().unwrap();
                let (q, hex) = match f[2].as_str() {
                    "key" => (
                        Fetch::Key {
                            session: SessionId(n(3) as u32),
                            pkt_seq: n(4) as u32,
                        },
                        &f[5],
                    ),
                    "range" => (
                        Fetch::Range {
                            dst: n(3) as u8,
                            from: n(4),
                            to: n(5),
                        },
                        &f[6],
                    ),
                    "block" => (
                        Fetch::Block {
                            height: Height(n(3)),
                        },
                        &f[4],
                    ),
                    "redirect" => (
                        Fetch::Redirect {
                            session: SessionId(n(3) as u32),
                            resend_from: n(4) as u32,
                            down: n(5) as u8,
                            to: n(6) as u8,
                        },
                        &f[7],
                    ),
                    k => panic!("fetch kind {k}"),
                };
                let want = unhex(hex);
                assert_eq!(&q.encode()[..], &want[..], "{}", f[1]);
                assert_eq!(Fetch::decode(&want).unwrap(), q, "{}", f[1]);
                ok += 1;
            }
            "fetch_err" => {
                let e = Fetch::decode(&unhex(&f[2])).unwrap_err();
                assert_eq!(format!("{e:?}"), f[3], "{}", f[1]);
                err += 1;
            }
            _ => {}
        }
    }
    assert_eq!((ok, err), (4, 12));
}

#[test]
fn dedupe_matches_the_published_vectors() {
    let mut n = 0;
    for f in lines().into_iter().filter(|f| f[0] == "dedupe") {
        let mut d = Dedupe::default();
        let seqs = f[2].split(',').map(|s| s.parse::<u32>().unwrap());
        let want = f[3].split(',');
        for (q, w) in seqs.zip(want) {
            let got = match d.mark(SessionId(1), q) {
                Seen::New => "New",
                Seen::Repeat => "Repeat",
                Seen::Late => "Late",
            };
            assert_eq!(got, w, "{} pkt_seq {q}", f[1]);
        }
        n += 1;
    }
    assert_eq!(n, 5);
}

#[test]
fn authenticated_fetches_match_the_published_vectors() {
    let key = |h: &str| -> [u8; 16] { unhex(h).try_into().unwrap() };
    let (mut ok, mut err) = (0, 0);
    for f in lines() {
        match f[0].as_str() {
            "fetch_auth" => {
                let (k, plain, sealed) = (key(&f[2]), unhex(&f[3]), unhex(&f[4]));
                let q = Fetch::decode(&plain).unwrap();
                assert_eq!(&q.seal(&k)[..], &sealed[..], "seal {}", f[1]);
                assert_eq!(Fetch::open(&sealed, &k).unwrap(), q, "open {}", f[1]);
                ok += 1;
            }
            "fetch_auth_err" => {
                let e = Fetch::open(&unhex(&f[3]), &key(&f[2])).unwrap_err();
                assert_eq!(format!("{e:?}"), f[4], "{}", f[1]);
                err += 1;
            }
            _ => {}
        }
    }
    assert_eq!((ok, err), (4, 4));
}

#[test]
fn redirects_match_the_published_vectors() {
    use vyrn_data::redirect::Redirect;
    let key = |h: &str| -> [u8; 16] { unhex(h).try_into().unwrap() };
    let (mut ok, mut err) = (0, 0);
    for f in lines() {
        match f[0].as_str() {
            "redirect" => {
                let n = |i: usize| f[i].parse::<u64>().unwrap();
                let r = Redirect {
                    down: n(3) as u8,
                    to: n(4) as u8,
                    session: SessionId(n(5) as u32),
                    resend_from: n(6) as u32,
                };
                let (k, want) = (key(&f[2]), unhex(&f[7]));
                assert_eq!(&r.seal(&k)[..], &want[..], "seal {}", f[1]);
                assert_eq!(Redirect::open(&want, &k).unwrap(), r, "open {}", f[1]);
                ok += 1;
            }
            "redirect_err" => {
                let e = Redirect::open(&unhex(&f[3]), &key(&f[2])).unwrap_err();
                assert_eq!(format!("{e:?}"), f[4], "{}", f[1]);
                err += 1;
            }
            _ => {}
        }
    }
    assert_eq!((ok, err), (2, 6));
}

/// V19 of the 04 §11 protocol vectors: the `DataRedirect` of 04 §7.6, sealed under the test
/// `K_seq` (bytes 00..0f) for session A.
#[test]
fn v19_of_the_protocol_vectors_opens_and_reseals() {
    use vyrn_data::redirect::Redirect;
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/vyrn_proto_vectors.out"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut rows = text.lines().skip_while(|l| !l.starts_with("V19 "));
    assert!(rows.next().unwrap().ends_with("(24 B)"));
    let bytes: Vec<u8> = rows
        .take(2)
        .flat_map(|l| l.trim().split_once(": ").unwrap().1.split(' '))
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect();
    let k_seq: [u8; 16] = core::array::from_fn(|i| i as u8);
    let r = Redirect::open(&bytes, &k_seq).unwrap();
    let want = Redirect {
        down: 0,
        to: 1,
        session: SessionId(0x0010_3007),
        resend_from: 5,
    };
    assert_eq!(r, want);
    assert_eq!(want.seal(&k_seq).as_slice(), bytes.as_slice());
    let k_out: [u8; 16] = core::array::from_fn(|i| 16 + i as u8);
    assert!(Redirect::open(&bytes, &k_out).is_err());
}

/// REDIRECT_BATCH (kind 5): encode, decode, seal and open against the published bytes.
#[test]
fn redirect_batches_match_the_published_vectors() {
    use vyrn_data::frame::{FetchMsg, MAX_BATCH, RedirectBatch};
    let key = |h: &str| -> [u8; 16] { unhex(h).try_into().unwrap() };
    let (mut ok, mut err, mut auth) = (0, 0, 0);
    for f in lines() {
        match f[0].as_str() {
            "batch_ok" => {
                let (down, to) = (f[2].parse().unwrap(), f[3].parse().unwrap());
                let entries: Vec<(SessionId, u32)> = f[4]
                    .split(',')
                    .map(|e| {
                        let (s, r) = e.split_once(':').unwrap();
                        (SessionId(s.parse().unwrap()), r.parse().unwrap())
                    })
                    .collect();
                let want = unhex(&f[5]);
                assert_eq!(
                    RedirectBatch::encode(down, to, &entries).unwrap(),
                    want,
                    "{}",
                    f[1]
                );
                let b = RedirectBatch::decode(&want).unwrap();
                assert_eq!((b.down, b.to), (down, to), "{}", f[1]);
                assert_eq!(b.entries().collect::<Vec<_>>(), entries, "{}", f[1]);
                assert_eq!(FetchMsg::decode(&want), Ok(FetchMsg::Batch(b)), "{}", f[1]);
                ok += 1;
            }
            "batch_err" => {
                let e = RedirectBatch::decode(&unhex(&f[2])).unwrap_err();
                assert_eq!(format!("{e:?}"), f[3], "{}", f[1]);
                err += 1;
            }
            "batch_auth" => {
                let (k, plain, sealed) = (key(&f[2]), unhex(&f[3]), unhex(&f[4]));
                let b = RedirectBatch::decode(&plain).unwrap();
                let e: Vec<_> = b.entries().collect();
                assert_eq!(RedirectBatch::seal(&k, b.down, b.to, &e).unwrap(), sealed);
                assert_eq!(RedirectBatch::open(&sealed, &k), Ok(b));
                assert_eq!(FetchMsg::open(&sealed, &k), Ok(FetchMsg::Batch(b)));
                auth += 1;
            }
            "batch_auth_err" => {
                let e = RedirectBatch::open(&unhex(&f[3]), &key(&f[2])).unwrap_err();
                assert_eq!(format!("{e:?}"), f[4], "{}", f[1]);
                auth += 1;
            }
            _ => {}
        }
    }
    assert_eq!((ok, err, auth), (3, 13, 6));
    assert_eq!(MAX_BATCH, 181);
}
