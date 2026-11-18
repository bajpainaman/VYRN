//! The drop-copy Noise transport (10 §8.5 item 5) against `dc_noise_vectors.txt`, written by
//! `gen_dc_noise_vectors.py` (an independent model): both handshake messages, the handshake
//! hash and every transport message byte for byte, from both ends; then tampering, the wrong
//! server key, a low-order key and resuming a read after a timeout.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{Read, Write};

use vyrn_md::dropcopy::noise::{NoiseError, NoiseStream, Transport, initiate, respond};
use vyrn_types::BookId;

const VECTORS: &str = include_str!("dc_noise_vectors.txt");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().unwrap()
}

#[derive(Default)]
struct Case {
    name: String,
    book: u16,
    s: [u8; 32],
    spub: [u8; 32],
    ie: [u8; 32],
    re: [u8; 32],
    m1: Vec<u8>,
    m2: Vec<u8>,
    hash: Vec<u8>,
    msgs: Vec<(bool, Vec<u8>, Vec<u8>)>,
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    let mut c = Case::default();
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let w: Vec<&str> = line.split_whitespace().collect();
        match w[0] {
            "noise" => {
                c = Case {
                    name: w[1].into(),
                    ..Case::default()
                }
            }
            "book" => c.book = w[1].parse().unwrap(),
            "s" => c.s = arr(w[1]),
            "spub" => c.spub = arr(w[1]),
            "ie" => c.ie = arr(w[1]),
            "re" => c.re = arr(w[1]),
            "m1" => c.m1 = unhex(w[1]),
            "m2" => c.m2 = unhex(w[1]),
            "hash" => c.hash = unhex(w[1]),
            "c2s" | "s2c" => c.msgs.push((w[0] == "c2s", unhex(w[1]), unhex(w[2]))),
            "end" => out.push(std::mem::take(&mut c)),
            x => panic!("line {x}"),
        }
    }
    out
}

fn both(c: &Case) -> (Transport, Transport) {
    let book = BookId(c.book);
    assert_eq!(vyrn_crypto::x25519::public_key(&c.s), c.spub, "{}", c.name);
    let (st, m1) = initiate(book, &c.spub, &c.ie).unwrap();
    assert_eq!(m1.to_vec(), c.m1, "{}: m1", c.name);
    let (server, m2) = respond(book, &c.s, &c.re, &m1).unwrap();
    assert_eq!(m2.to_vec(), c.m2, "{}: m2", c.name);
    let client = st.finish(&m2).unwrap();
    assert_eq!(client.handshake_hash().to_vec(), c.hash, "{}: hash", c.name);
    assert_eq!(server.handshake_hash().to_vec(), c.hash, "{}: hash", c.name);
    (client, server)
}

#[test]
fn handshake_and_transport_match_the_vectors() {
    let cs = cases();
    assert_eq!(cs.len(), 2);
    for c in &cs {
        let (mut client, mut server) = both(c);
        assert_eq!(c.msgs.len(), 6);
        for (i, (c2s, pt, framed)) in c.msgs.iter().enumerate() {
            let (tx, rx) = if *c2s {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
            let mut out = Vec::new();
            tx.seal(pt, &mut out).unwrap();
            assert_eq!(&out, framed, "{} message {i}: seal", c.name);
            let mut body = framed[2..].to_vec();
            let n = rx.open(&mut body).unwrap();
            assert_eq!(&body[..n], &pt[..], "{} message {i}: open", c.name);
        }
    }
}

#[test]
fn tampering_the_wrong_key_and_a_low_order_key_fail() {
    let c = &cases()[0];
    let book = BookId(c.book);
    let m1: [u8; 48] = c.m1.clone().try_into().unwrap();
    // A flipped bit anywhere in message 1 (key or tag) fails at the server.
    for i in [0, 31, 32, 47] {
        let mut m = m1;
        m[i] ^= 1;
        assert!(respond(book, &c.s, &c.re, &m).is_err(), "byte {i}");
    }
    // Another book's server, or a client that has the wrong server key, never completes.
    assert_eq!(
        respond(BookId(c.book + 1), &c.s, &c.re, &m1).err(),
        Some(NoiseError::Auth)
    );
    let (_, m1x) = initiate(book, &[9; 32], &c.ie).unwrap();
    assert_eq!(
        respond(book, &c.s, &c.re, &m1x).err(),
        Some(NoiseError::Auth)
    );
    // A low-order ephemeral key (the all-zero point) is refused before any tag.
    let mut z = m1;
    z[..32].fill(0);
    assert_eq!(respond(book, &c.s, &c.re, &z).err(), Some(NoiseError::Key));
    // A tampered message 2 fails at the client.
    let (st, _) = initiate(book, &c.spub, &c.ie).unwrap();
    let mut m2: [u8; 48] = c.m2.clone().try_into().unwrap();
    m2[40] ^= 0x80;
    assert_eq!(st.finish(&m2).err(), Some(NoiseError::Auth));
    // A transport message replayed, reordered or flipped fails.
    let (mut client, mut server) = both(c);
    let (mut a, mut b) = (Vec::new(), Vec::new());
    server.seal(b"one", &mut a).unwrap();
    server.seal(b"two", &mut b).unwrap();
    let mut bb = b[2..].to_vec();
    assert_eq!(
        client.open(&mut bb).err(),
        Some(NoiseError::Auth),
        "reordered"
    );
    let (mut client, _) = both(c);
    let mut aa = a[2..].to_vec();
    aa[0] ^= 1;
    assert_eq!(
        client.open(&mut aa).err(),
        Some(NoiseError::Auth),
        "flipped"
    );
}

/// A pipe whose reads, once `chop` is set, hand out at most 7 bytes and a `WouldBlock`
/// between them, as a socket read timeout does.
struct Choppy {
    rx: std::collections::VecDeque<u8>,
    tx: Vec<u8>,
    chop: bool,
    block: bool,
}

impl Read for Choppy {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.chop {
            self.block = !self.block;
            if self.block {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
        }
        if self.rx.is_empty() {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let cap = if self.chop { 7 } else { usize::MAX };
        let n = buf.len().min(cap).min(self.rx.len());
        for b in buf.iter_mut().take(n) {
            *b = self.rx.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Write for Choppy {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_stream_read_resumes_after_a_timeout_mid_message() {
    let c = &cases()[0];
    // The server's handshake reply, then its first three transport messages.
    let s2c: Vec<&(bool, Vec<u8>, Vec<u8>)> = c.msgs.iter().filter(|m| !m.0).collect();
    let mut wire = vec![0, 48];
    wire.extend_from_slice(&c.m2);
    let io = Choppy {
        rx: wire.into_iter().collect(),
        tx: Vec::new(),
        chop: false,
        block: false,
    };
    let mut s = NoiseStream::connect(io, BookId(c.book), &c.spub, &c.ie).unwrap();
    assert_eq!(s.get_mut().tx[..2], [0, 48]);
    assert_eq!(s.get_mut().tx[2..], c.m1[..]);
    for m in &s2c[..3] {
        s.get_mut().rx.extend(m.2.iter().copied());
    }
    s.get_mut().chop = true;
    let want: Vec<u8> = s2c[..3].iter().flat_map(|m| m.1.clone()).collect();
    let mut got = Vec::new();
    let mut buf = [0u8; 5];
    let mut blocks = 0;
    while got.len() < want.len() {
        match s.read(&mut buf) {
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => blocks += 1,
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!(got, want);
    assert!(blocks > 10, "reads were interrupted mid-message: {blocks}");
}

/// A whole session inside Noise over TCP: handshake, HELLO, signed login, ACCEPT, records and
/// the heartbeat, as `vyrn-dropcopy` serves it; and a client with the wrong server key never
/// reaches the HELLO.
#[test]
fn a_session_runs_inside_noise_over_tcp() {
    use std::sync::{Arc, RwLock};
    use std::time::Duration;
    use vyrn_md::dropcopy::StreamId;
    use vyrn_md::dropcopy::server::{DcStore, Keys, Session, Wake, serve};
    use vyrn_md::dropcopy::wire::{FRAME_BYTES, Frame, FrameKind, Login};
    use vyrn_md::dropcopy::{DcOut, DcRecord};
    use vyrn_types::{AccountId, Epoch};
    let book = BookId(7);
    let (s, spub) = ([0x44; 32], vyrn_crypto::x25519::public_key(&[0x44; 32]));
    let seed = [1u8; 32];
    let mut keys = Keys::new();
    keys.add(AccountId(1), vyrn_crypto::ed25519::public_key(&seed), None);
    let own = StreamId {
        account: AccountId(1),
        master: false,
    };
    let mut st = DcStore::new();
    st.begin_epoch(Epoch(1));
    for q in 1..=3 {
        st.push(own, q, &DcRecord::eod(AccountId(1), 0, [q, 0, 0, 0, 0]));
    }
    let store = Arc::new(RwLock::new(st));
    let wake = Arc::new(Wake::new());
    let keys = Arc::new(keys);
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let (st2, w2, k2) = (Arc::clone(&store), Arc::clone(&wake), Arc::clone(&keys));
    let server = std::thread::spawn(move || {
        for (i, c) in l.incoming().take(2).enumerate() {
            let c = c.unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let r = NoiseStream::accept(c, book, &s, &[0x50 + i as u8; 32]).and_then(|mut c| {
                serve(
                    &mut c,
                    Session::new(book, [7; 32]),
                    &k2,
                    &st2,
                    &w2,
                    Duration::from_secs(5),
                    |c, d| {
                        c.get_mut().set_read_timeout(Some(d))?;
                        c.get_mut().set_write_timeout(Some(d))
                    },
                )
            });
            if i == 1 {
                // The wrong server key: message 1's tag fails here.
                let e = r.unwrap_err();
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{e}");
            }
        }
    });
    let tcp = std::net::TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut c = NoiseStream::connect(tcp, book, &spub, &[0x60; 32]).unwrap();
    let mut f = [0u8; FRAME_BYTES];
    c.read_exact(&mut f).unwrap();
    assert_eq!(Frame::decode(&f).unwrap().kind, FrameKind::Hello);
    let login = Login {
        master: false,
        book,
        account: AccountId(1),
        epoch: Epoch(1),
        from: 2,
        signer: AccountId(1),
        challenge: [7; 32],
    };
    c.write_all(&login.encode_signed(&seed)).unwrap();
    let mut got = Vec::new();
    for _ in 0..4 {
        c.read_exact(&mut f).unwrap();
        let fr = Frame::decode(&f).unwrap();
        got.push((fr.kind, fr.seq));
    }
    assert_eq!(got[0].0, FrameKind::Accept);
    assert_eq!(
        &got[1..3],
        &[(FrameKind::Record, 2), (FrameKind::Record, 3)]
    );
    assert_eq!(got[3], (FrameKind::Heartbeat, 3));
    drop(c);
    // A client that holds another server key: the handshake fails and it reads nothing.
    let tcp = std::net::TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let bad = vyrn_crypto::x25519::public_key(&[0x45; 32]);
    assert!(NoiseStream::connect(tcp, book, &bad, &[0x61; 32]).is_err());
    server.join().unwrap();
}
