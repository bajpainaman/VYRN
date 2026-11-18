//! Checks the derived feeds against `feed_vectors.txt`, which `gen_feed_vectors.py` wrote from
//! spec 10 §7 and the crate's labeled readings with no Rust involved:
//! `python3 -I crates/vyrn-md/tests/gen_feed_vectors.py crates/vyrn-md/tests`.

use vyrn_md::{
    BookOp, DeleteCause, Event, EventKind, Feed, LevelEncoder, MboEncoder, MboSubscriber,
    MboWindow, Order, Packet, Resume, RetxRequest, Side, SnapEncoder, SnapReader, Snapshot,
    StatsEncoder, TradesEncoder, mbo_c_decode, mbo_c_encode,
};
use vyrn_types::{BookId, Epoch, Nanos, Qty, StepId, StepKind, Tick};

const BOOK: BookId = BookId(7);
const EPOCH: Epoch = Epoch(0x0001_0003);

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn num(s: &str) -> u64 {
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).unwrap(),
        None => s.parse().unwrap(),
    }
}

fn u32_(s: &str) -> u32 {
    u32::try_from(num(s)).unwrap()
}

fn side(s: &str) -> Side {
    if num(s) == 0 { Side::Buy } else { Side::Sell }
}

fn op(w: &[&str]) -> BookOp {
    match w[0] {
        "add" => BookOp::Add {
            oid: u32_(w[1]),
            side: side(w[2]),
            tick: Tick(u32_(w[3])),
            qty: Qty(u32_(w[4])),
            prio_ts: Nanos(num(w[5])),
            via_bbo: num(w[6]) == 1,
            auction: num(w[7]) == 1,
        },
        "del" => BookOp::Delete {
            oid: u32_(w[1]),
            cause: DeleteCause::from_code(u8::try_from(num(w[2])).unwrap()).unwrap(),
            tick: Tick(u32_(w[3])),
            qty: Qty(u32_(w[4])),
        },
        "reduce" => BookOp::Reduce {
            oid: u32_(w[1]),
            tick: Tick(u32_(w[2])),
            qty_after: Qty(u32_(w[3])),
        },
        k => panic!("op {k}"),
    }
}

/// `<ts> <kind> ...` (the words after `ev` or `out`).
fn event(w: &[&str]) -> Event {
    let a = &w[1..];
    let kind = match a[0] {
        "lane" => EventKind::LaneOp(op(&a[1..])),
        "stepop" => EventKind::StepOp(op(&a[1..])),
        "step" => EventKind::Step {
            step: StepId(num(a[1])),
            kind: StepKind::from_code(u8::try_from(num(a[2])).unwrap()).unwrap(),
            n_exec: u16::try_from(num(a[3])).unwrap(),
            taker: u32_(a[4]),
        },
        "exec" => EventKind::Exec {
            aggressor: side(a[1]),
            ordinal: u16::try_from(num(a[2])).unwrap(),
            maker: u32_(a[3]),
            tick: Tick(u32_(a[4])),
            qty: Qty(u32_(a[5])),
        },
        "bust" => EventKind::Bust {
            step: StepId(num(a[1])),
            ordinal: u16::try_from(num(a[2])).unwrap(),
            tick: Tick(u32_(a[3])),
            qty: Qty(u32_(a[4])),
        },
        "status" => EventKind::Status {
            status: vyrn_md::BookStatus::from_code(u8::try_from(num(a[1])).unwrap()).unwrap(),
            epoch: Epoch(u32_(a[2])),
        },
        "tick" => EventKind::TimerTick,
        k => panic!("event {k}"),
    };
    Event {
        rx_ts: Nanos(num(w[0])),
        kind,
    }
}

#[derive(Default)]
struct Case {
    name: String,
    feed: String,
    param: Option<u64>,
    ev: Vec<Event>,
    out: Vec<Event>,
    pkt: Vec<String>,
    orders: Vec<Vec<u64>>,
    input: Vec<u8>,
    snap: Option<Snapshot>,
    req: Vec<String>,
}

fn cases() -> Vec<Case> {
    let mut all = vec![];
    let mut c = Case::default();
    for line in include_str!("feed_vectors.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "case" => {
                c = Case {
                    name: w[1].into(),
                    feed: w[2].into(),
                    param: w.get(3).map(|x| num(x)),
                    ..Case::default()
                }
            }
            "ev" => c.ev.push(event(&w[1..])),
            "out" => c.out.push(event(&w[1..])),
            "pkt" => c.pkt.push(w[1].into()),
            "order" => c.orders.push(w[1..].iter().map(|x| num(x)).collect()),
            "in" => c.input = unhex(w[1]),
            "snap" => {
                c.snap = Some(Snapshot {
                    as_of: StepId(num(w[1])),
                    orders: vec![],
                    resume: vec![],
                });
                c.param = Some(num(w[2]));
            }
            "sorder" => {
                let now = Nanos(c.param.unwrap());
                c.snap.as_mut().unwrap().orders.push((
                    u32_(w[1]),
                    Order {
                        side: side(w[2]),
                        tick: Tick(u32_(w[3])),
                        qty: Qty(u32_(w[4])),
                        prio_ts: now,
                    },
                ));
            }
            "resume" => c.snap.as_mut().unwrap().resume.push(Resume {
                channel: u8::try_from(num(w[1])).unwrap(),
                record: u16::try_from(num(w[2])).unwrap(),
                seq: num(w[3]),
            }),
            "req" => c.req = w[1..].iter().map(|x| x.to_string()).collect(),
            "endcase" => all.push(std::mem::take(&mut c)),
            k => panic!("line {k}"),
        }
    }
    all
}

fn hexes(p: &[Vec<u8>]) -> Vec<String> {
    p.iter().map(|x| hex(x)).collect()
}

#[test]
fn feeds_match_the_published_vectors() {
    let all = cases();
    assert_eq!(all.len(), 18);
    for c in &all {
        let mut got: Vec<Vec<u8>> = vec![];
        let mut s = c.ev.iter().copied();
        let name = format!("{} {}", c.name, c.feed);
        match c.feed.as_str() {
            "mbp10" => LevelEncoder::mbp10(BOOK, EPOCH)
                .run(&mut s, &mut got)
                .unwrap(),
            "tob" => LevelEncoder::tob(BOOK, EPOCH)
                .run(&mut s, &mut got)
                .unwrap(),
            "trades" => TradesEncoder::new(BOOK, EPOCH)
                .run(&mut s, &mut got)
                .unwrap(),
            "stats" => StatsEncoder::new(BOOK, EPOCH, c.ev[0].rx_ts)
                .run(&mut s, &mut got)
                .unwrap(),
            "mbow" => {
                let mut w = MboWindow::new(u32::try_from(c.param.unwrap()).unwrap());
                let mut out = vec![];
                for e in &c.ev {
                    w.push(e, &mut out).unwrap();
                }
                assert_eq!(out, c.out, "{name}");
                // The windowed stream is an ordinary MBO stream under feed 8.
                MboEncoder::with_feed(Feed::MboW, BOOK, EPOCH)
                    .run(&mut out.iter().copied(), &mut got)
                    .unwrap();
                let mut sub = MboSubscriber::with_feed(Feed::MboW, BOOK, EPOCH);
                for p in &got {
                    assert_eq!(p[1], Feed::MboW.code(), "{name}");
                    sub.on_packet(p).unwrap();
                }
                sub.finish().unwrap();
                let held: Vec<Vec<u64>> = sub
                    .book()
                    .orders()
                    .iter()
                    .map(|(oid, o)| {
                        vec![
                            u64::from(*oid),
                            o.side as u64,
                            u64::from(o.tick.0),
                            u64::from(o.qty.0),
                            o.prio_ts.0,
                        ]
                    })
                    .collect();
                assert_eq!(held, c.orders, "{name}");
                continue;
            }
            "mboc" => {
                let mut out = vec![];
                mbo_c_encode(&c.input, &mut out).unwrap();
                assert_eq!(vec![hex(&out)], c.pkt, "{name}");
                let back = mbo_c_decode(&out).unwrap();
                let orig = Packet::decode(&c.input).unwrap();
                assert_eq!(back.records, orig.records, "{name}");
                assert_eq!(back.header.seq, orig.header.seq, "{name}");
                continue;
            }
            "snap" => {
                let snap = c.snap.as_ref().unwrap();
                SnapEncoder::new(Feed::Mbo, BOOK, EPOCH).publish(
                    snap,
                    Nanos(c.param.unwrap()),
                    &mut got,
                );
                let mut r = SnapReader::new(Feed::Mbo, BOOK, EPOCH);
                let mut read = None;
                for p in &got {
                    read = r.on_packet(p).unwrap().or(read);
                }
                assert_eq!(read.as_ref(), Some(snap), "{name}");
            }
            "retx" => {
                let b: [u8; 24] = unhex(&c.req[0]).try_into().unwrap();
                let r = RetxRequest::decode(&b).unwrap();
                let f: Vec<u64> = c.req[1..].iter().map(|x| num(x)).collect();
                assert_eq!(
                    [
                        u64::from(r.channel.code()),
                        u64::from(r.book.0),
                        u64::from(r.epoch16),
                        r.from_seq,
                        r.to_seq
                    ],
                    f[..]
                );
                assert_eq!(r.encode(), b);
                continue;
            }
            f => panic!("feed {f}"),
        }
        assert_eq!(hexes(&got), c.pkt, "{name}");
    }
}

#[test]
fn snapshot_reader_rejects_a_bad_hash() {
    let snap = Snapshot {
        as_of: StepId(3),
        orders: vec![],
        resume: vec![Resume {
            channel: 0,
            record: 0,
            seq: 1,
        }],
    };
    let mut got: Vec<Vec<u8>> = vec![];
    SnapEncoder::new(Feed::Mbo, BOOK, EPOCH).publish(&snap, Nanos(1), &mut got);
    let last = got[0].len() - 1;
    got[0][last] ^= 1;
    assert_eq!(
        SnapReader::new(Feed::Mbo, BOOK, EPOCH).on_packet(&got[0]),
        Err(vyrn_md::SnapError::Hash)
    );
}
