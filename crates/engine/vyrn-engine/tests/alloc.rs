//! The sealing allocator (11 §3.5) as the global allocator of this test binary, and
//! `INV-NOALLOC` on the live path: after setup, ingest, steps and boundaries allocate nothing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod harness;

use harness::*;
use vyrn_bbo::admit::NeverLate;
use vyrn_bbo::{ControlCmd, Phase, Record, Side, Tif, TxEntry};
use vyrn_engine::alloc::{SealingAlloc, seal_counting, unseal, violations};
use vyrn_engine::{Rec, Sink};
use vyrn_lane::{RespPkt, RxIn};
use vyrn_types::{Epoch, LaneId, MAX_REQ_PAYLOAD, Nanos, Tick};
use vyrn_wire::{ReqHeader, encode_request};

#[global_allocator]
static A: SealingAlloc = SealingAlloc;

#[test]
fn counting_seal_counts_alloc_and_free_on_this_thread_only() {
    seal_counting();
    let before = violations();
    let b = std::hint::black_box(Box::new(7u64));
    drop(b);
    let n = violations() - before;
    unseal();
    assert_eq!(n, 2, "one alloc, one dealloc");
    // Unsealed: not counted.
    let before = violations();
    drop(std::hint::black_box(vec![1u8; 16]));
    assert_eq!(violations(), before);
}

/// Counts outputs without allocating.
#[derive(Default)]
struct Count {
    recs: usize,
    resp: usize,
    tx: usize,
}

impl Sink for Count {
    fn record(&mut self, _r: &Rec<'_>) {
        self.recs += 1;
    }
    fn lane_resp(&mut self, _l: LaneId, _p: &RespPkt) {
        self.resp += 1;
    }
    fn tx(&mut self, _h: &TxEntry, _r: &[Record]) {
        self.tx += 1;
    }
}

#[test]
fn the_live_path_does_not_allocate_after_setup() {
    let (bbo, mut sh) = new_box();
    let mut e = engine(bbo, &mut sh);
    let pkts: Vec<(usize, u64, Vec<u8>)> = [
        (0, 1, new(Side::Sell, Tif::Day, 105, 5, 1)),
        (1, 1, new(Side::Buy, Tif::Day, 105, 2, 2)),
        (2, 1, new(Side::Buy, Tif::Ioc, 105, 1, 3)),
        (0, 2, new(Side::Buy, Tif::Day, 90, 1, 4)),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (l, a, m))| {
        // Each (lane, session) sends once: pkt_seq 1.
        let hdr = ReqHeader::new(sid(l, a as u32), 1, Epoch(0).low16(), BOOK, false);
        let mut buf = [0u8; MAX_REQ_PAYLOAD];
        let n = encode_request(&mut buf, hdr, &[m], &kseq(l, a as u32), None).unwrap();
        (l, 1_000 * (i as u64 + 1), buf[..n].to_vec())
    })
    .collect();
    let mut sink = Count::default();
    seal_counting();
    let before = violations();
    for (l, rx_ts, bytes) in &pkts {
        let rx = RxIn {
            bytes,
            rx_ts: Nanos(*rx_ts),
            pkt_hash: fake_hash(bytes),
        };
        e.ingest(*l, rx, &NeverLate, &mut sink).unwrap();
        e.run(&NeverLate, &mut sink, 64).unwrap();
    }
    let n = violations() - before;
    unseal();
    assert!(sink.recs > 8 && sink.tx > 0, "the run did work");
    assert_eq!(n, 0, "allocator calls on the sealed thread");
}

/// The uncross and its auction-only remainders (05 §8.8 item 6) run on the sealed engine
/// thread too: ending a remainder at B2 allocates nothing (#193 review 1, Vercel).
#[test]
fn an_uncross_with_auction_only_remainders_does_not_allocate() {
    let (bbo, mut sh) = new_box();
    let mut e = engine(bbo, &mut sh);
    let mut sink = Count::default();
    assert!(e.command(&ControlCmd::Phase {
        phase: Phase::Auction,
        lo: Tick(0),
        hi: Tick(0),
    }));
    e.run(&NeverLate, &mut sink, 64).unwrap();
    let pkts: Vec<(usize, u64, Vec<u8>)> = [
        (0, 1, new(Side::Sell, Tif::Day, 104, 2, 1)),
        (1, 1, new(Side::Buy, Tif::Day, 106, 2, 2)),
        (2, 1, new(Side::Buy, Tif::AuctionOnly, 100, 3, 3)),
        (2, 2, new(Side::Buy, Tif::AuctionOnly, 99, 4, 4)),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (l, a, m))| {
        let hdr = ReqHeader::new(sid(l, a as u32), 1, Epoch(0).low16(), BOOK, false);
        let mut buf = [0u8; MAX_REQ_PAYLOAD];
        let n = encode_request(&mut buf, hdr, &[m], &kseq(l, a as u32), None).unwrap();
        (l, 1_000 * (i as u64 + 1), buf[..n].to_vec())
    })
    .collect();
    for (l, rx_ts, bytes) in &pkts {
        let rx = RxIn {
            bytes,
            rx_ts: Nanos(*rx_ts),
            pkt_hash: fake_hash(bytes),
        };
        e.ingest(*l, rx, &NeverLate, &mut sink).unwrap();
        e.run(&NeverLate, &mut sink, 64).unwrap();
    }
    let resp = sink.resp;
    seal_counting();
    let before = violations();
    for c in [
        ControlCmd::Phase {
            phase: Phase::Frozen,
            lo: Tick(1),
            hi: Tick(u32::MAX - 1),
        },
        ControlCmd::Uncross {
            price: Tick(105),
            qty: 2,
        },
    ] {
        assert!(e.command(&c));
        e.run(&NeverLate, &mut sink, 64).unwrap();
    }
    let n = violations() - before;
    unseal();
    assert!(
        sink.resp > resp,
        "the uncross sent fills and the Out records"
    );
    assert_eq!(n, 0, "allocator calls on the sealed thread");
}
