//! Checks the drop copy against `dc_vectors.txt`, which `gen_dc_vectors.py` wrote from spec 10
//! §8 and the crate's labeled readings with no Rust involved:
//! `python3 -I crates/vyrn-md/tests/gen_dc_vectors.py crates/vyrn-md/tests`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::panic
)]

use std::collections::BTreeMap;

use vyrn_bbo::{OrderFlags, Record as Resp, Side as BSide, Stp, Tif, TxEntry};
use vyrn_md::dropcopy::server::{DcStore, Keys, Session};
use vyrn_md::dropcopy::wire::{FRAME_BYTES, Frame, LOGIN_BYTES, Login};
use vyrn_md::dropcopy::{
    Alloc, AllocAsset, Balances, DC_REC_BYTES, DcAccount, DcConfig, DcOut, DcRecord, DcRoute,
    DropCopy, StreamId,
};
use vyrn_md::{Tap, TapOp, TapSrc, TapStep, TapTaker};
use vyrn_types::{
    AccountId, BookId, Epoch, Handle, Height, LaneId, LaneSeq, Qty, RejectReason, SessionId,
    StepId, StepKind, Tick,
};
use vyrn_wire::Msg;

const BOOK: BookId = BookId(7);
const VECTORS: &str = include_str!("dc_vectors.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn num(s: &str) -> u64 {
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).unwrap(),
        None => s.parse().unwrap(),
    }
}

fn n32(s: &str) -> u32 {
    u32::try_from(num(s)).unwrap()
}

fn msg(w: &[&str]) -> Msg {
    match w[0] {
        "new" => {
            let side = if num(w[1]) == 0 {
                BSide::Buy
            } else {
                BSide::Sell
            };
            let f = OrderFlags::new(side, Tif::Day, false, Stp::None).0;
            Msg::New {
                flags: vyrn_wire::OrderFlags::from_byte(f).unwrap(),
                tick: Tick(n32(w[2])),
                qty: Qty(n32(w[3])),
                client_tag: n32(w[4]),
            }
        }
        "cancel" => Msg::Cancel {
            handle: Handle(n32(w[1])),
            client_tag: n32(w[2]),
        },
        "reduce" => Msg::Reduce {
            handle: Handle(n32(w[1])),
            by: Qty(n32(w[2])),
            client_tag: n32(w[3]),
        },
        x => panic!("msg {x}"),
    }
}

fn rec(w: &[&str]) -> Resp {
    let index = u8::try_from(num(w[1])).unwrap();
    match w[0] {
        "ack" => Resp::Ack {
            index,
            handle: Handle(n32(w[2])),
            tick: Tick(n32(w[3])),
            client_tag: n32(w[4]),
        },
        "cxl" => Resp::CancelAck {
            index,
            handle: Handle(n32(w[2])),
            canceled: Qty(n32(w[3])),
            client_tag: n32(w[4]),
        },
        "out" => Resp::Out {
            index,
            cause: u16::try_from(num(w[2])).unwrap(),
            handle: Handle(n32(w[3])),
            qty: Qty(n32(w[4])),
            client_tag: n32(w[5]),
        },
        "fill" => Resp::Fill {
            index,
            liq: u8::try_from(num(w[2])).unwrap(),
            handle: Handle(n32(w[3])),
            tick: Tick(n32(w[4])),
            qty: Qty(n32(w[5])),
        },
        "rej" => Resp::Reject {
            index,
            reason: RejectReason::from_code(u16::try_from(num(w[2])).unwrap()).unwrap(),
            detail: 0,
            client_tag: 0,
        },
        x => panic!("rec {x}"),
    }
}

/// `head | msg | rec` split on `|`.
fn parts(line: &str) -> Vec<Vec<&str>> {
    line.split('|')
        .map(|p| p.split_whitespace().collect())
        .collect()
}

type Recs = Vec<(StreamId, u64, DcRecord)>;

/// A `rescan` taker being read, up to `taken`.
#[derive(Default)]
struct Taker {
    step: StepId,
    lane: LaneId,
    seq: LaneSeq,
    session: SessionId,
    prior: u32,
    msg: Option<Msg>,
    fills: Vec<(u32, Resp)>,
    rest: Option<(u32, Resp)>,
    makers: Vec<(TxEntry, Resp, u16)>,
}

struct Pending {
    step: StepId,
    kind: StepKind,
    flags: u8,
    src: Option<TapSrc>,
    tx: Vec<(TxEntry, Resp)>,
}

/// Runs one `case` block; returns its streams and checks them against the expected `rec`s.
fn run_case(lines: &[&str]) -> Recs {
    let mut cfg = DcConfig {
        book: BOOK,
        tick_size: 0,
        accounts: Vec::new(),
    };
    let mut i = 0;
    while let Some(w) = lines
        .get(i)
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
    {
        match w[0] {
            "tick_size" => cfg.tick_size = num(w[1]),
            "acct" => cfg.accounts.push(DcAccount {
                account: AccountId(n32(w[1])),
                master: (w[2] != "-").then(|| AccountId(n32(w[2]))),
                sessions: vec![SessionId(n32(w[3]))],
                taker_ppm: w[4].parse().unwrap(),
                maker_ppm: w[5].parse().unwrap(),
                msg_fee_improve: n32(w[6]),
                msg_fee_cross: n32(w[7]),
            }),
            _ => break,
        }
        i += 1;
    }
    let mut dc = DropCopy::new(&cfg, Recs::new());
    let mut pend: Option<Pending> = None;
    let mut taker = Taker::default();
    let mut bal: BTreeMap<AccountId, Balances> = BTreeMap::new();
    let mut want = Recs::new();
    for line in &lines[i..] {
        let p = parts(line);
        let h = &p[0];
        match h[0] {
            "op" => dc.lane_op(&TapOp {
                lane: LaneId(u8::try_from(num(h[1])).unwrap()),
                seq: LaneSeq(num(h[2])),
                session: SessionId(n32(h[3])),
                pkt_seq: 0,
                resp_seq: n32(h[4]),
                msg: Some(msg(&p[1])),
                rec: rec(&p[2]),
            }),
            "step" => {
                let src = (h[4] != "-").then(|| TapSrc {
                    lane: LaneId(u8::try_from(num(h[4])).unwrap()),
                    seq: LaneSeq(num(h[5])),
                    session: SessionId(n32(h[6])),
                    msg: Some(msg(&p[1])),
                });
                pend = Some(Pending {
                    step: StepId(num(h[1])),
                    kind: StepKind::from_code(u8::try_from(num(h[2])).unwrap()).unwrap(),
                    flags: u8::try_from(num(h[3])).unwrap(),
                    src,
                    tx: Vec::new(),
                });
            }
            "tx" => {
                let st = pend.as_mut().unwrap();
                let e = TxEntry {
                    step: st.step,
                    session: SessionId(n32(h[3])),
                    resp_seq: n32(h[4]),
                    lane: LaneId(u8::try_from(num(h[2])).unwrap()),
                    role: u8::try_from(num(h[1])).unwrap(),
                    ..TxEntry::default()
                };
                st.tx.push((e, rec(&p[1])));
            }
            "release" => {
                let st = pend.take().unwrap();
                dc.step(&TapStep {
                    step: st.step,
                    kind: st.kind,
                    flags: st.flags,
                    src: st.src,
                    tx: &st.tx,
                });
            }
            "rescan" => {
                taker = Taker {
                    step: StepId(num(h[1])),
                    lane: LaneId(u8::try_from(num(h[2])).unwrap()),
                    seq: LaneSeq(num(h[3])),
                    session: SessionId(n32(h[4])),
                    prior: n32(h[5]),
                    msg: Some(msg(&p[1])),
                    ..Taker::default()
                };
            }
            "tfill" => taker.fills.push((n32(h[1]), rec(&p[1]))),
            "trest" => taker.rest = Some((n32(h[1]), rec(&p[1]))),
            "tmaker" => taker.makers.push((
                TxEntry {
                    step: taker.step,
                    session: SessionId(n32(h[3])),
                    resp_seq: n32(h[4]),
                    lane: LaneId(u8::try_from(num(h[2])).unwrap()),
                    role: u8::try_from(num(h[1])).unwrap(),
                    ..TxEntry::default()
                },
                rec(&p[1]),
                u16::try_from(num(h[5])).unwrap(),
            )),
            "taken" => {
                let t = std::mem::take(&mut taker);
                dc.rescan_taker(&TapTaker {
                    step: t.step,
                    lane: t.lane,
                    seq: t.seq,
                    session: t.session,
                    pkt_seq: 0,
                    msg: t.msg,
                    prior: t.prior,
                    fills: &t.fills,
                    rest: t.rest,
                    makers: &t.makers,
                });
            }
            "final" => dc.final_block(Height(num(h[1])), StepId(num(h[2]))),
            "bal" => {
                bal.insert(
                    AccountId(n32(h[1])),
                    Balances {
                        quote_free: num(h[2]),
                        quote_resv: num(h[3]),
                        base_free: num(h[4]),
                        base_resv: num(h[5]),
                    },
                );
            }
            "alloc" => dc.alloc(Alloc {
                step: StepId(num(h[1])),
                account: AccountId(n32(h[2])),
                asset: if num(h[3]) == 0 {
                    AllocAsset::Quote
                } else {
                    AllocAsset::Base
                },
                debit: h[4] == "1",
                amount: num(h[5]),
            }),
            "revert" => dc.revert_after(StepId(num(h[1]))),
            "route" => dc.route(&DcRoute {
                account: AccountId(n32(h[1])),
                lane_seq: num(h[2]),
                index: u8::try_from(num(h[3])).unwrap(),
                session: SessionId(n32(h[4])),
                resp_seq: n32(h[5]),
                asset: u8::try_from(num(h[6])).unwrap(),
                to_book: BookId(u16::try_from(num(h[7])).unwrap()),
                amount: num(h[8]),
                client_tag: n32(h[9]),
                fee: h[10].parse().unwrap(),
            }),
            "end" => dc
                .end_epoch(|a| bal.get(&a).copied().unwrap_or_default())
                .unwrap(),
            "settled" => dc.settled(Height(num(h[1])), StepId(num(h[2]))),
            "rec" => {
                let b: [u8; DC_REC_BYTES] = unhex(h[4]).try_into().unwrap();
                want.push((
                    StreamId {
                        account: AccountId(n32(h[1])),
                        master: h[2] == "1",
                    },
                    num(h[3]),
                    DcRecord::decode(&b).unwrap(),
                ));
            }
            x => panic!("line {x}"),
        }
    }
    assert_eq!(dc.error(), None);
    let got = dc.into_out().unwrap();
    for (k, (g, w)) in got.iter().zip(&want).enumerate() {
        assert_eq!(g, w, "record {k}");
    }
    assert_eq!(got.len(), want.len());
    got
}

fn blocks(kind: &str) -> Vec<Vec<&'static str>> {
    let mut out = Vec::new();
    let mut cur: Option<Vec<&str>> = None;
    for l in VECTORS.lines() {
        if l.starts_with(kind) {
            cur = Some(vec![l]);
        } else if l.starts_with("end") && l.ends_with(&kind[..kind.len() - 1]) {
            out.push(cur.take().unwrap());
        } else if let Some(c) = cur.as_mut() {
            c.push(l);
        }
    }
    out
}

#[test]
fn streams_match_the_vectors() {
    let cases = blocks("case ");
    assert_eq!(cases.len(), 6);
    for c in &cases {
        run_case(&c[1..]);
    }
}

#[test]
fn sessions_match_the_vectors() {
    let mut store = DcStore::new();
    let mut keys = Keys::new();
    let mut epoch = None;
    for l in VECTORS.lines() {
        let w: Vec<_> = l.split_whitespace().collect();
        match w.first() {
            Some(&"store") => {
                let e = Epoch(n32(w[1]));
                if epoch != Some(e) {
                    store.begin_epoch(e);
                    epoch = Some(e);
                }
                let b: [u8; DC_REC_BYTES] = unhex(w[5]).try_into().unwrap();
                let id = StreamId {
                    account: AccountId(n32(w[2])),
                    master: w[3] == "1",
                };
                store.push(id, num(w[4]), &DcRecord::decode(&b).unwrap());
            }
            Some(&"key") => {
                let seed: [u8; 32] = unhex(w[2]).try_into().unwrap();
                let pk: [u8; 32] = unhex(w[4]).try_into().unwrap();
                assert_eq!(vyrn_crypto::ed25519::public_key(&seed), pk, "RFC 8032 key");
                let master = (w[3] != "-").then(|| AccountId(n32(w[3])));
                keys.add(AccountId(n32(w[1])), pk, master);
            }
            Some(&"heartbeat") => {
                let b: [u8; FRAME_BYTES] = unhex(w[1]).try_into().unwrap();
                let f = Frame::decode(&b).unwrap();
                assert_eq!(f.encode(), b);
            }
            _ => {}
        }
    }
    let sessions = blocks("session ");
    assert!(sessions.len() >= 15);
    for s in &sessions {
        let head: Vec<_> = s[0].split_whitespace().collect();
        let name = head[1];
        let challenge: [u8; 32] = unhex(head[2]).try_into().unwrap();
        let mut sess = Session::new(BOOK, challenge);
        let hello = s[1].strip_prefix("hello ").unwrap();
        assert_eq!(hex(&sess.hello(&store).encode()), hello, "{name}: hello");
        let raw: [u8; LOGIN_BYTES] = unhex(s[2].strip_prefix("login ").unwrap())
            .try_into()
            .unwrap();
        let mut got = vec![sess.login(&raw, &keys, &store)];
        got.extend(sess.poll(&store, 10_000));
        let got: Vec<String> = got.iter().map(|f| hex(&f.encode())).collect();
        let want: Vec<String> = s[3..]
            .iter()
            .map(|l| l.strip_prefix("frame ").unwrap().to_owned())
            .collect();
        assert_eq!(got, want, "{name}");
        // Frames round-trip; the Rust signer gives the generator's bytes (RFC 8032 is
        // deterministic).
        for f in &want {
            let b: [u8; FRAME_BYTES] = unhex(f).try_into().unwrap();
            assert_eq!(Frame::decode(&b).unwrap().encode(), b, "{name}");
        }
        if name == "own" {
            let (l, _) = Login::decode(&raw).unwrap();
            assert_eq!(l.encode_signed(&[1; 32]), raw);
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn own(a: u32) -> StreamId {
    StreamId {
        account: AccountId(a),
        master: false,
    }
}

/// A session that falls behind the replay window is told so and closed, not left idle.
#[test]
fn a_session_whose_epoch_is_evicted_is_rejected() {
    let seed = [1u8; 32];
    let mut keys = Keys::new();
    keys.add(AccountId(1), vyrn_crypto::ed25519::public_key(&seed), None);
    let mut store = DcStore::new();
    store.begin_epoch(Epoch(1));
    store.push(own(1), 1, &DcRecord::eod(AccountId(1), 0, [0; 5]));
    let ch = [9u8; 32];
    let mut sess = Session::new(BOOK, ch);
    let login = Login {
        master: false,
        book: BOOK,
        account: AccountId(1),
        epoch: Epoch(1),
        from: 1,
        signer: AccountId(1),
        challenge: ch,
    };
    let acc = sess.login(&login.encode_signed(&seed), &keys, &store);
    assert_eq!(acc.kind, vyrn_md::dropcopy::wire::FrameKind::Accept);
    assert_eq!(sess.poll(&store, 10).len(), 1);
    store.begin_epoch(Epoch(2));
    store.begin_epoch(Epoch(3));
    let f = sess.poll(&store, 10);
    assert_eq!(f.len(), 1);
    assert_eq!(
        f[0].reason(),
        Some(vyrn_md::dropcopy::wire::RejectReason::Epoch)
    );
    assert!(sess.closed());
    assert!(sess.tick().is_none(), "no heartbeat for a closed session");
}

/// A login dripped one byte at a time cannot outlast the login deadline.
#[test]
// The client paces its drip with a sleep; nothing on a control thread here.
#[allow(clippy::disallowed_methods)]
fn a_slow_login_is_cut_off_at_the_deadline() {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let client = std::thread::spawn(move || {
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        let mut hello = [0u8; FRAME_BYTES];
        c.read_exact(&mut hello).unwrap();
        for _ in 0..40 {
            if c.write_all(&[0]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let (mut s, _) = l.accept().unwrap();
    let store = std::sync::RwLock::new(DcStore::new());
    let t = Instant::now();
    let r = vyrn_md::dropcopy::server::serve(
        &mut s,
        Session::new(BOOK, [0; 32]),
        &Keys::new(),
        &store,
        &vyrn_md::dropcopy::server::Wake::new(),
        Duration::from_millis(300),
        |c, d| c.set_read_timeout(Some(d)),
    );
    let took = t.elapsed();
    assert!(r.is_err(), "{r:?}");
    assert!(took < Duration::from_millis(1_000), "{took:?}");
    drop(s);
    client.join().unwrap();
}

/// Master balances that do not fit u64 are an error, not a clamped EOD.
#[test]
fn master_balance_overflow_is_an_error() {
    let acct = |a: u32| DcAccount {
        account: AccountId(a),
        master: Some(AccountId(9)),
        sessions: vec![SessionId(a)],
        taker_ppm: 0,
        maker_ppm: 0,
        msg_fee_improve: 0,
        msg_fee_cross: 0,
    };
    let cfg = DcConfig {
        book: BOOK,
        tick_size: 1,
        accounts: vec![acct(1), acct(2)],
    };
    let dc = DropCopy::new(&cfg, Recs::new());
    let r = dc.finish(|_| Balances {
        quote_free: u64::MAX,
        ..Balances::default()
    });
    assert_eq!(r.err(), Some(vyrn_md::dropcopy::DcError::Overflow));
}

/// A logged-in session on a real socket: the client end, the server thread, the store.
struct Live {
    client: std::net::TcpStream,
    server: std::thread::JoinHandle<std::io::Result<()>>,
    store: std::sync::Arc<std::sync::RwLock<DcStore>>,
    wake: std::sync::Arc<vyrn_md::dropcopy::server::Wake>,
}

fn live_session(records: u64) -> Live {
    use std::io::{Read, Write};
    use std::sync::{Arc, RwLock};
    use vyrn_md::dropcopy::server::{Wake, serve};
    let seed = [1u8; 32];
    let mut keys = Keys::new();
    keys.add(AccountId(1), vyrn_crypto::ed25519::public_key(&seed), None);
    let mut st = DcStore::new();
    st.begin_epoch(Epoch(1));
    st.open(own(1));
    for q in 1..=records {
        st.push(own(1), q, &DcRecord::eod(AccountId(1), 0, [q, 0, 0, 0, 0]));
    }
    let store = Arc::new(RwLock::new(st));
    let wake = Arc::new(Wake::new());
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (mut s, _) = l.accept().unwrap();
    let (st2, w2) = (Arc::clone(&store), Arc::clone(&wake));
    let server = std::thread::spawn(move || {
        serve(
            &mut s,
            Session::new(BOOK, [7; 32]),
            &keys,
            &st2,
            &w2,
            std::time::Duration::from_secs(5),
            |c, d| {
                c.set_read_timeout(Some(d))?;
                c.set_write_timeout(Some(d))
            },
        )
    });
    let mut hello = [0u8; FRAME_BYTES];
    client.read_exact(&mut hello).unwrap();
    let login = Login {
        master: false,
        book: BOOK,
        account: AccountId(1),
        epoch: Epoch(1),
        from: 1,
        signer: AccountId(1),
        challenge: [7; 32],
    };
    client.write_all(&login.encode_signed(&seed)).unwrap();
    Live {
        client,
        server,
        store,
        wake,
    }
}

/// A record pushed while the session waits goes out at once, not at the next heartbeat.
#[test]
fn a_new_record_wakes_the_session() {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let mut x = live_session(0);
    let mut f = [0u8; FRAME_BYTES];
    x.client.read_exact(&mut f).unwrap(); // ACCEPT
    // Let the server reach its wait, right after a heartbeat window opened.
    x.client
        .set_read_timeout(Some(Duration::from_millis(30)))
        .unwrap();
    assert!(x.client.read_exact(&mut f).is_err(), "nothing to send yet");
    x.client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let t = Instant::now();
    x.store
        .write()
        .unwrap()
        .push(own(1), 1, &DcRecord::eod(AccountId(1), 0, [0; 5]));
    x.wake.bump();
    x.client.read_exact(&mut f).unwrap();
    let took = t.elapsed();
    let fr = Frame::decode(&f).unwrap();
    assert_eq!(
        (fr.kind, fr.seq),
        (vyrn_md::dropcopy::wire::FrameKind::Record, 1)
    );
    assert!(took < Duration::from_millis(20), "{took:?}");
    drop(x.client);
    let _ = x.server.join();
}

/// A subscriber that stops reading a large replay is dropped by the write timeout.
#[test]
fn a_stalled_subscriber_is_dropped() {
    use std::time::{Duration, Instant};
    let x = live_session(200_000); // 12.8 MB of frames: more than the socket buffers hold
    let t = Instant::now();
    let r = x.server.join().unwrap();
    assert!(r.is_err(), "{r:?}");
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    drop(x.client);
}
