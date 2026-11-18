//! Checks the codec and the encoder against `record_vectors.txt` and `mbo_vectors.txt`, which an
//! independent Python script wrote from spec 10 §7.3–§7.5 (no Rust involved), so any
//! implementation of the feed can use the same files.

use vyrn_md::{BookOp, DeleteCause, Event, EventKind, MboEncoder, MboSubscriber, Record, Side};
use vyrn_types::{BookId, Epoch, Nanos, Qty, StepId, StepKind, Tick};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn lines(file: &str) -> impl Iterator<Item = &str> {
    file.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
}

/// The canonical text form of the vector file.
fn describe(r: &Record) -> String {
    let s = |x: Side| x as u8;
    let b = u8::from;
    match *r {
        Record::Add {
            side,
            via_bbo,
            auction,
            ts_delta,
            oid,
            tick,
            qty,
        } => format!(
            "add side={} bbo={} auction={} ts={ts_delta} oid={oid} tick={} qty={}",
            s(side),
            b(via_bbo),
            b(auction),
            tick.0,
            qty.0
        ),
        Record::Delete {
            cause,
            oid,
            tick,
            qty,
        } => {
            format!(
                "delete cause={} oid={oid} tick={} qty={}",
                cause.code(),
                tick.0,
                qty.0
            )
        }
        Record::Reduce { oid, tick, qty } => {
            format!("reduce oid={oid} tick={} qty={}", tick.0, qty.0)
        }
        Record::Sync { step } => format!("sync step={}", step.0),
        Record::Step {
            kind,
            n_exec,
            step,
            taker,
        } => {
            format!(
                "step kind={} n_exec={n_exec} step={} taker={taker}",
                kind.code(),
                step.0
            )
        }
        Record::Exec {
            aggressor,
            ordinal,
            maker,
            tick,
            qty,
        } => format!(
            "exec side={} ordinal={ordinal} oid={maker} tick={} qty={}",
            s(aggressor),
            tick.0,
            qty.0
        ),
        Record::Bust { ordinal, step } => format!("bust ordinal={ordinal} step={}", step.0),
        Record::Status {
            status,
            epoch,
            step,
        } => {
            format!(
                "status status={} epoch={} step={}",
                status.code(),
                epoch.0,
                step.0
            )
        }
        Record::Attest {
            kind,
            height_low,
            last_step,
        } => {
            format!(
                "attest kind={} height={height_low} step={}",
                kind.code(),
                last_step.0
            )
        }
        Record::Level {
            side,
            level,
            empty,
            orders,
            tick,
            qty,
        } => format!(
            "level side={} level={level} empty={} orders={orders} tick={} qty={qty}",
            s(side),
            b(empty),
            tick.0
        ),
        Record::Trade {
            aggressor,
            auction,
            ts_delta,
            step_delta,
            ordinal,
            tick,
            qty,
        } => format!(
            "trade side={} auction={} ts={ts_delta} step_delta={step_delta} ordinal={ordinal} tick={} qty={}",
            s(aggressor),
            b(auction),
            tick.0,
            qty.0
        ),
        Record::TradeBust {
            step_delta,
            ordinal,
            tick,
            qty,
        } => format!(
            "trade_bust step_delta={step_delta} ordinal={ordinal} tick={} qty={}",
            tick.0, qty.0
        ),
        Record::Stat {
            stat,
            second,
            value,
        } => {
            format!("stat stat={stat} second={second} value={value}")
        }
        Record::SnapBegin {
            feed,
            n_records,
            as_of,
        } => {
            format!(
                "snap_begin feed={} n={n_records} step={}",
                feed.code(),
                as_of.0
            )
        }
        Record::SnapResume {
            channel,
            record,
            seq,
        } => {
            format!("snap_resume channel={channel} record={record} seq={seq}")
        }
        Record::SnapEnd { hash8 } => format!("snap_end hash={}", hex(&hash8)),
    }
}

#[test]
fn records_match_the_published_vectors() {
    let mut n = 0;
    for line in lines(include_str!("record_vectors.txt")) {
        let f: Vec<&str> = line.splitn(4, ' ').collect();
        let (name, bytes, status, want) = (f[0], unhex(f[1]), f[2], f[3]);
        let arr: [u8; 16] = bytes.as_slice().try_into().unwrap();
        match (Record::decode(&arr), status) {
            (Ok(r), "ok") => {
                assert_eq!(describe(&r), want, "{name}");
                assert_eq!(r.encode(), arr, "{name}: re-encode");
            }
            (Err(e), "err") => assert_eq!(format!("{e:?}"), want, "{name}"),
            (got, _) => panic!("{name}: got {got:?}, want {status} {want}"),
        }
        n += 1;
    }
    assert_eq!(n, 42);
}

fn num(s: &str) -> u64 {
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).unwrap(),
        None => s.parse().unwrap(),
    }
}

fn side(s: &str) -> Side {
    if num(s) == 0 { Side::Buy } else { Side::Sell }
}

fn op(w: &[&str]) -> BookOp {
    let u = |i: usize| u32::try_from(num(w[i])).unwrap();
    match w[0] {
        "add" => BookOp::Add {
            oid: u(1),
            side: side(w[2]),
            tick: Tick(u(3)),
            qty: Qty(u(4)),
            prio_ts: Nanos(num(w[5])),
            via_bbo: num(w[6]) == 1,
            auction: num(w[7]) == 1,
        },
        "del" => BookOp::Delete {
            oid: u(1),
            cause: DeleteCause::from_code(u8::try_from(num(w[2])).unwrap()).unwrap(),
            tick: Tick(u(3)),
            qty: Qty(u(4)),
        },
        "reduce" => BookOp::Reduce {
            oid: u(1),
            tick: Tick(u(2)),
            qty_after: Qty(u(3)),
        },
        k => panic!("op {k}"),
    }
}

#[test]
fn mbo_packets_match_the_published_vector() {
    let file = include_str!("mbo_vectors.txt");
    let (mut book, mut epoch) = (0, 0);
    let (mut events, mut want, mut orders) = (vec![], vec![], vec![]);
    for line in lines(file) {
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "book" => book = num(w[1]),
            "epoch" => epoch = num(w[1]),
            "ev" => {
                let a = &w[2..];
                let kind = match a[0] {
                    "lane" => EventKind::LaneOp(op(&a[1..])),
                    "stepop" => EventKind::StepOp(op(&a[1..])),
                    "step" => EventKind::Step {
                        step: StepId(num(a[1])),
                        kind: StepKind::from_code(u8::try_from(num(a[2])).unwrap()).unwrap(),
                        n_exec: u16::try_from(num(a[3])).unwrap(),
                        taker: u32::try_from(num(a[4])).unwrap(),
                    },
                    "exec" => EventKind::Exec {
                        aggressor: side(a[1]),
                        ordinal: u16::try_from(num(a[2])).unwrap(),
                        maker: u32::try_from(num(a[3])).unwrap(),
                        tick: Tick(u32::try_from(num(a[4])).unwrap()),
                        qty: Qty(u32::try_from(num(a[5])).unwrap()),
                    },
                    "tick" => EventKind::TimerTick,
                    k => panic!("event {k}"),
                };
                events.push(Event {
                    rx_ts: Nanos(num(w[1])),
                    kind,
                });
            }
            "end" => {}
            "pkt" => want.push(w[1].to_string()),
            "order" => orders.push(w[1..].iter().map(|x| num(x)).collect::<Vec<_>>()),
            k => panic!("line {k}"),
        }
    }
    let (book, epoch) = (
        BookId(u16::try_from(book).unwrap()),
        Epoch(u32::try_from(epoch).unwrap()),
    );

    let mut got: Vec<Vec<u8>> = vec![];
    MboEncoder::new(book, epoch)
        .run(&mut events.into_iter(), &mut got)
        .unwrap();
    let got_hex: Vec<String> = got.iter().map(|p| hex(p)).collect();
    assert_eq!(got_hex, want);

    let mut sub = MboSubscriber::new(book, epoch);
    for p in &want {
        sub.on_packet(&unhex(p)).unwrap();
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
    assert_eq!(held, orders);
}
