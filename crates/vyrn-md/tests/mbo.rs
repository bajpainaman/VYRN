//! The encoder's flush rules and reject reasons, and the merge rule (10 §7.4) under every
//! delivery order: a subscriber rebuilds the replayed book whatever the interleaving of channels.

use std::collections::BTreeMap;

use vyrn_md::{
    BookOp, DeleteCause, Event, EventKind, MboEncoder, MboSubscriber, NO_WATERMARK, Packet, Record,
    Side, StreamError, SubError, oid,
};
use vyrn_types::{BookId, Epoch, LaneId, Nanos, Qty, StepId, StepKind, Tick};

const BOOK: BookId = BookId(3);
const EPOCH: Epoch = Epoch(0x0002_0005);

fn add(lane: u8, slot: u32, ts: u64) -> Event {
    Event {
        rx_ts: Nanos(ts),
        kind: EventKind::LaneOp(BookOp::Add {
            oid: oid(LaneId(lane), slot),
            side: Side::Buy,
            tick: Tick(100),
            qty: Qty(1),
            prio_ts: Nanos(ts),
            via_bbo: false,
            auction: false,
        }),
    }
}

fn step(n: u64, n_exec: u16, ts: u64) -> Event {
    Event {
        rx_ts: Nanos(ts),
        kind: EventKind::Step {
            step: StepId(n),
            kind: StepKind::Improve,
            n_exec,
            taker: 0,
        },
    }
}

fn encode(events: &[Event]) -> Vec<Packet> {
    let mut out: Vec<Vec<u8>> = vec![];
    MboEncoder::new(BOOK, EPOCH)
        .run(&mut events.iter().copied(), &mut out)
        .unwrap();
    out.iter().map(|b| Packet::decode(b).unwrap()).collect()
}

/// (channel, count, step_base) of each packet.
fn shape(p: &[Packet]) -> Vec<(u8, u16, u64)> {
    p.iter()
        .map(|p| (p.header.channel.index, p.header.count, p.header.step_base))
        .collect()
}

#[test]
fn rule_a_closes_at_88_records() {
    let ev: Vec<Event> = (0..89).map(|i| add(0, i, 10)).collect();
    let p = encode(&ev);
    // Closed inside interval 0: no watermark yet. Then the epoch-end packets.
    assert_eq!(p[0].header.count, 88);
    assert_eq!(p[0].header.step_base, NO_WATERMARK);
    assert_eq!(
        shape(&p[1..]),
        [(0, 1, 0), (1, 0, 0), (2, 0, 0), (3, 0, 0), (4, 0, 0)]
    );
}

#[test]
fn rule_b_closes_after_a_quiet_interval() {
    // Lane 1 writes in interval 0 only; step 1 adds to the step channel; step 2 ends interval 1,
    // which added nothing to lane channel 1, so its packet closes with W = 1.
    let p = encode(&[add(1, 0, 0), step(1, 0, 10), step(2, 0, 20)]);
    assert_eq!(shape(&p[..1]), [(1, 1, 1)]);
    // The step channel was busy in interval 1, so it waits for the epoch end.
    assert_eq!(p.iter().filter(|p| p.header.channel.index == 4).count(), 1);
}

#[test]
fn rule_c_closes_an_old_packet() {
    // Both intervals add to channel 0, but at the end of interval 0 its first record is
    // MD_FLUSH_NS older than the newest rx_ts of that interval.
    let p = encode(&[
        add(0, 0, 0),
        add(0, 1, 1_000),
        step(1, 0, 1_000),
        add(0, 2, 1_001),
    ]);
    assert_eq!(shape(&p[..1]), [(0, 2, 0)]);
    // Age is judged by the newest rx_ts inside the interval, not the next step's (spec gap 5).
    let p = encode(&[
        add(0, 0, 0),
        add(0, 1, 999),
        step(1, 0, 5_000),
        add(0, 2, 5_001),
    ]);
    let lane0: Vec<_> = shape(&p).into_iter().filter(|s| s.0 == 0).collect();
    assert_eq!(lane0, [(0, 4, 1)], "one packet, sent only at the epoch end");
}

#[test]
fn rule_d_closes_when_ts_delta_does_not_fit() {
    let p = encode(&[add(2, 0, 5), add(2, 1, 5 + 65_535), add(2, 2, 5 + 65_536)]);
    assert_eq!(shape(&p[..1]), [(2, 2, NO_WATERMARK)]);
    assert_eq!(p[0].header.ts_base, Nanos(5));
    let Record::Add { ts_delta, .. } = p[0].records[1] else {
        panic!()
    };
    assert_eq!(ts_delta, 65_535);
}

#[test]
fn lane_ops_carry_their_sync_position() {
    let p = encode(&[
        add(0, 0, 0),
        step(1, 0, 1),
        step(2, 0, 2),
        add(0, 1, 3),
        add(0, 2, 4),
    ]);
    let lane0: Vec<&Packet> = p.iter().filter(|p| p.header.channel.index == 0).collect();
    let r = &lane0.last().unwrap().records;
    assert!(matches!(r[0], Record::Sync { step: StepId(2) }), "{r:?}");
    assert_eq!(r.len(), 3, "one MD_SYNC per interval, not per record");
}

#[test]
fn heartbeats_only_on_idle_channels() {
    let tick = |ts| Event {
        rx_ts: Nanos(ts),
        kind: EventKind::TimerTick,
    };
    let mut out: Vec<Vec<u8>> = vec![];
    let mut enc = MboEncoder::new(BOOK, EPOCH);
    for ev in [add(0, 0, 0), step(1, 0, 1), tick(2)] {
        enc.push(&ev, &mut out).unwrap();
    }
    let p: Vec<Packet> = out.iter().map(|b| Packet::decode(b).unwrap()).collect();
    // Channels 0 and 4 hold records; 1–3 send a heartbeat whose watermark is step 1 − 1.
    assert_eq!(shape(&p), [(1, 0, 0), (2, 0, 0), (3, 0, 0)]);
}

#[test]
fn encoder_rejects_a_broken_stream() {
    let exec = Event {
        rx_ts: Nanos(5),
        kind: EventKind::Exec {
            aggressor: Side::Sell,
            ordinal: 0,
            maker: 0,
            tick: Tick(1),
            qty: Qty(1),
        },
    };
    let run = |ev: &[Event]| {
        let mut out: Vec<Vec<u8>> = vec![];
        let mut enc = MboEncoder::new(BOOK, EPOCH);
        for e in ev {
            enc.push(e, &mut out)?;
        }
        enc.finish(&mut out)
    };
    assert_eq!(run(&[step(2, 0, 0)]), Err(StreamError::StepOrder));
    assert_eq!(
        run(&[add(0, 0, 9), add(0, 1, 8)]),
        Err(StreamError::TimeBackwards)
    );
    assert_eq!(run(&[exec]), Err(StreamError::OutsideStep));
    assert_eq!(run(&[step(1, 0, 0), exec]), Err(StreamError::ExecCount));
    assert_eq!(
        run(&[step(1, 2, 0), exec, step(2, 0, 6)]),
        Err(StreamError::ExecCount)
    );
    assert_eq!(run(&[step(1, 1, 0)]), Err(StreamError::ExecCount));
    assert_eq!(run(&[step(1, 1, 0), exec]), Ok(()));
}

#[test]
fn subscriber_rejects_gaps_and_misplaced_records() {
    let mut out: Vec<Vec<u8>> = vec![];
    MboEncoder::new(BOOK, EPOCH)
        .run(&mut [add(0, 0, 0), add(0, 1, 70_000)].into_iter(), &mut out)
        .unwrap();
    // out[0] and out[1] are channel 0's seq 1 and 2.
    let mut sub = MboSubscriber::new(BOOK, EPOCH);
    assert_eq!(sub.on_packet(&out[1]), Err(SubError::Gap { channel: 0 }));
    assert_eq!(
        MboSubscriber::new(BookId(9), EPOCH).on_packet(&out[0]),
        Err(SubError::WrongBook)
    );

    let mut p = Packet::decode(&out[0]).unwrap();
    p.records[0] = Record::Exec {
        aggressor: Side::Buy,
        ordinal: 0,
        maker: 1,
        tick: Tick(1),
        qty: Qty(1),
    };
    assert_eq!(
        MboSubscriber::new(BOOK, EPOCH).on_packet(&p.encode()),
        Err(SubError::WrongChannel)
    );

    let mut sub = MboSubscriber::new(BOOK, EPOCH);
    sub.on_packet(&out[0]).unwrap();
    assert_eq!(sub.finish(), Err(SubError::Incomplete));
}

#[test]
fn finish_waits_for_the_step_channel() {
    let exec = Event {
        rx_ts: Nanos(2),
        kind: EventKind::Exec {
            aggressor: Side::Sell,
            ordinal: 0,
            maker: oid(LaneId(1), 0),
            tick: Tick(100),
            qty: Qty(1),
        },
    };
    let mut out: Vec<Vec<u8>> = vec![];
    MboEncoder::new(BOOK, EPOCH)
        .run(
            &mut [add(1, 0, 0), step(1, 1, 1), exec].into_iter(),
            &mut out,
        )
        .unwrap();
    let (step_pkts, lane_pkts): (Vec<_>, Vec<_>) = out.into_iter().partition(|p| p[0] == 4);
    let mut sub = MboSubscriber::new(BOOK, EPOCH);
    for p in &lane_pkts {
        sub.on_packet(p).unwrap();
    }
    // Every lane says W = 1, but step 1 has not arrived.
    assert_eq!(sub.finish(), Err(SubError::Incomplete));
    for p in &step_pkts {
        sub.on_packet(p).unwrap();
    }
    sub.finish().unwrap();
    assert!(sub.book().orders().is_empty());
}

#[test]
fn a_rejected_duplicate_add_keeps_the_live_order() {
    let mut book = vyrn_md::Book::default();
    let add = |qty| Record::Add {
        side: Side::Buy,
        via_bbo: false,
        auction: false,
        ts_delta: 0,
        oid: 7,
        tick: Tick(100),
        qty: Qty(qty),
    };
    book.apply(&add(10), Nanos(0)).unwrap();
    assert_eq!(
        book.apply(&add(99), Nanos(0)),
        Err(vyrn_md::BookError::DuplicateOid)
    );
    assert_eq!(book.orders()[&7].qty, Qty(10));
}

/// xorshift64*: the test needs no rand dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

type RefBook = BTreeMap<u32, (Side, u32, u32, u64)>;

/// A random but valid replay stream and the book it leaves, applied strictly in event order.
fn scenario(rng: &mut Rng, n: usize) -> (Vec<Event>, RefBook) {
    let mut book = RefBook::new();
    let mut ev = vec![];
    let mut next_slot = [0u32; 12];
    let (mut ts, mut step_n) = (0u64, 0u64);
    let pick = |rng: &mut Rng, book: &RefBook, lane: Option<u8>| {
        let live: Vec<u32> = book
            .keys()
            .copied()
            .filter(|o| lane.is_none_or(|l| o >> 24 == u32::from(l)))
            .collect();
        (!live.is_empty()).then(|| live[usize::try_from(rng.below(live.len() as u64)).unwrap()])
    };
    for _ in 0..n {
        ts += rng.below(1_500);
        let lane = u8::try_from(rng.below(10)).unwrap();
        match rng.below(10) {
            0..=3 => {
                let o = oid(LaneId(lane), next_slot[usize::from(lane)]);
                next_slot[usize::from(lane)] += 1;
                let side = if rng.below(2) == 0 {
                    Side::Buy
                } else {
                    Side::Sell
                };
                let (tick, qty) = (
                    90 + u32::try_from(rng.below(20)).unwrap(),
                    1 + u32::try_from(rng.below(9)).unwrap(),
                );
                book.insert(o, (side, tick, qty, ts));
                ev.push(Event {
                    rx_ts: Nanos(ts),
                    kind: EventKind::LaneOp(BookOp::Add {
                        oid: o,
                        side,
                        tick: Tick(tick),
                        qty: Qty(qty),
                        prio_ts: Nanos(ts),
                        via_bbo: false,
                        auction: false,
                    }),
                });
            }
            4 | 5 => {
                let Some(o) = pick(rng, &book, Some(lane)) else {
                    continue;
                };
                let (side, tick, qty, prio) = book[&o];
                let kind = if qty > 1 && rng.below(2) == 0 {
                    book.insert(o, (side, tick, qty - 1, prio));
                    BookOp::Reduce {
                        oid: o,
                        tick: Tick(tick),
                        qty_after: Qty(qty - 1),
                    }
                } else {
                    book.remove(&o);
                    BookOp::Delete {
                        oid: o,
                        cause: DeleteCause::Cancel,
                        tick: Tick(tick),
                        qty: Qty(qty),
                    }
                };
                ev.push(Event {
                    rx_ts: Nanos(ts),
                    kind: EventKind::LaneOp(kind),
                });
            }
            6..=8 => {
                step_n += 1;
                let makers: std::collections::BTreeSet<u32> = (0..rng.below(4))
                    .filter_map(|_| pick(rng, &book, None))
                    .collect();
                let taker = oid(LaneId(11), next_slot[11]);
                next_slot[11] += 1;
                ev.push(Event {
                    rx_ts: Nanos(ts),
                    kind: EventKind::Step {
                        step: StepId(step_n),
                        kind: StepKind::Cross,
                        n_exec: u16::try_from(makers.len()).unwrap(),
                        taker,
                    },
                });
                for (i, m) in makers.iter().enumerate() {
                    let (side, tick, qty, prio) = book[m];
                    let q = 1 + u32::try_from(rng.below(u64::from(qty))).unwrap();
                    if q == qty {
                        book.remove(m);
                    } else {
                        book.insert(*m, (side, tick, qty - q, prio));
                    }
                    let aggressor = if side == Side::Buy {
                        Side::Sell
                    } else {
                        Side::Buy
                    };
                    ev.push(Event {
                        rx_ts: Nanos(ts),
                        kind: EventKind::Exec {
                            aggressor,
                            ordinal: u16::try_from(i).unwrap(),
                            maker: *m,
                            tick: Tick(tick),
                            qty: Qty(q),
                        },
                    });
                }
                if rng.below(2) == 0 {
                    // A resting residual whose priority is older than the step.
                    let prio = ts.saturating_sub(rng.below(70_000));
                    book.insert(taker, (Side::Buy, 95, 3, prio));
                    ev.push(Event {
                        rx_ts: Nanos(ts),
                        kind: EventKind::StepOp(BookOp::Add {
                            oid: taker,
                            side: Side::Buy,
                            tick: Tick(95),
                            qty: Qty(3),
                            prio_ts: Nanos(prio),
                            via_bbo: true,
                            auction: false,
                        }),
                    });
                }
            }
            _ => ev.push(Event {
                rx_ts: Nanos(ts),
                kind: EventKind::TimerTick,
            }),
        }
    }
    (ev, book)
}

#[test]
fn merge_rule_rebuilds_the_book_in_any_delivery_order() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for seed in 0..300 {
        let (events, want) = scenario(&mut rng, 400);
        let mut out: Vec<Vec<u8>> = vec![];
        MboEncoder::new(BOOK, EPOCH)
            .run(&mut events.iter().copied(), &mut out)
            .unwrap();

        // A and B are functions of the log: identical bytes.
        let mut again: Vec<Vec<u8>> = vec![];
        MboEncoder::new(BOOK, EPOCH)
            .run(&mut events.iter().copied(), &mut again)
            .unwrap();
        assert_eq!(out, again);

        // Deliver each channel in order, interleaving channels at random.
        let mut queues: Vec<Vec<Vec<u8>>> = vec![vec![]; 5];
        for p in out {
            queues[usize::from(p[0])].push(p);
        }
        for q in &mut queues {
            q.reverse();
        }
        let mut sub = MboSubscriber::new(BOOK, EPOCH);
        while queues.iter().any(|q| !q.is_empty()) {
            let c = usize::try_from(rng.below(5)).unwrap();
            if let Some(p) = queues[c].pop() {
                sub.on_packet(&p)
                    .unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
            }
        }
        sub.finish().unwrap();
        let got: RefBook = sub
            .book()
            .orders()
            .iter()
            .map(|(o, v)| (*o, (v.side, v.tick.0, v.qty.0, v.prio_ts.0)))
            .collect();
        assert_eq!(got, want, "seed {seed}");
    }
}
