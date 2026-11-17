//! The backend conformance suite: the contract of `vyrn_wire::ring` and 06 §6.1, checked through
//! the public traits only. Any backend runs it by implementing `Harness` and calling `run_all`
//! (or each check) from a test; `tests/conformance.rs` does that for `sim` and `kernel_udp`.
//!
//! Every check opens fresh queues, sends fast-path frames from a `TxRing` to an `RxRing` of the
//! same backend, and panics with a message naming the rule it found broken.
//!
//! | Check | Rule |
//! |---|---|
//! | `arrival_order` | 1: arrival order, `rx_ts` non-decreasing, at most `RX_BURST` per poll |
//! | `errors_are_counters` | 2: bad frames are counted, never `Err`; nothing fatal |
//! | `whole_frame_or_full` | 3: each send delivers the whole frame or returns `TxFull` |
//! | `release_order` | `release` frees the oldest frames first; a full ring holds new frames back |
//! | `forged_descriptors` | `bytes` is `&[]` for any descriptor the queue did not produce or released |

use core::net::{Ipv4Addr, SocketAddrV4};
use core::ptr::NonNull;
use std::time::{Duration, Instant};

use vyrn_types::Nanos;
use vyrn_wire::{RX_BURST, RxFlags, RxPkt, RxRing, TxFull, TxRing};

use crate::frame::{self, Endpoint, FrameHdr, MAX_FRAME_BYTES, MAX_PAYLOAD};
use crate::{ExtCounted, ExtCounters, NicBackend, NicConfig, PortId, RxBind, TxClass};

/// How long a check waits for frames a backend delivers asynchronously.
const WAIT: Duration = Duration::from_secs(5);
/// Polls that must all return nothing before a check concludes a frame is held back.
const IDLE_POLLS: usize = 200;

/// What the suite needs to know about a backend.
pub trait Harness {
    type Nic: NicBackend;
    /// A config for this backend with one port, `PortId(0)`.
    fn config(rx_slots: usize, tx_slots: usize) -> NicConfig;
    /// The bind of the `i`-th RX queue of one `Nic`; distinct `i` give distinct queues.
    fn bind(i: u16) -> RxBind;
    /// Where to address frames so they reach `rx`.
    fn dest(rx: &<Self::Nic as NicBackend>::Rx) -> SocketAddrV4;
}

type Rx<H> = <<H as Harness>::Nic as NicBackend>::Rx;
type Tx<H> = <<H as Harness>::Nic as NicBackend>::Tx;

struct Queue<H: Harness> {
    nic: H::Nic,
    rx: Rx<H>,
    tx: Tx<H>,
    dst: SocketAddrV4,
}

fn open<H: Harness>(rx_slots: usize, tx_slots: usize) -> Queue<H> {
    let mut nic = H::Nic::open(&H::config(rx_slots, tx_slots)).expect("open");
    let rx = nic.rx_ring(&H::bind(0)).expect("rx_ring");
    let tx = nic.tx_ring(PortId(0), TxClass::Fill).expect("tx_ring");
    let dst = H::dest(&rx);
    Queue { nic, rx, tx, dst }
}

/// A fast-path frame to `dst` whose payload starts with `seq` and has `extra` more bytes.
pub fn test_frame(dst: SocketAddrV4, seq: u32, extra: usize) -> Vec<u8> {
    let mut payload = seq.to_le_bytes().to_vec();
    payload.extend((0..extra).map(|i| (i as u32 ^ seq) as u8));
    let hdr = FrameHdr {
        src: Endpoint {
            mac: [2, 0, 0, 0, 0, 1],
            ip: Ipv4Addr::LOCALHOST,
            port: 9,
        },
        dst: Endpoint {
            mac: [2, 0, 0, 0, 0, 2],
            ip: *dst.ip(),
            port: dst.port(),
        },
    };
    let mut out = vec![0; frame::HDR_BYTES + payload.len()];
    frame::build(&hdr, &payload, &mut out).expect("test frame");
    out
}

fn payload_seq(bytes: &[u8]) -> (u32, Vec<u8>) {
    let p = frame::parse(bytes).expect("a received frame parses as fast-path");
    let seq = u32::from_le_bytes(p.payload[..4].try_into().expect("seq"));
    (seq, p.payload.to_vec())
}

fn send_ok(tx: &mut impl TxRing, f: &[u8]) {
    let t = Instant::now();
    while tx.send(f) == Err(TxFull) {
        tx.reap();
        assert!(t.elapsed() < WAIT, "send stayed TxFull after reaping");
        std::thread::yield_now();
    }
}

/// Polls until at least `n` frames have arrived, without releasing any. Returns the descriptors.
fn poll_n(rx: &mut impl RxRing, n: usize) -> Vec<RxPkt> {
    let mut got = Vec::new();
    let t = Instant::now();
    let mut out = [RxPkt::empty(); RX_BURST];
    while got.len() < n {
        let k = rx.poll(&mut out);
        assert!(k <= RX_BURST, "rule 1: poll returned {k} > RX_BURST frames");
        got.extend_from_slice(&out[..k]);
        if k == 0 {
            assert!(
                t.elapsed() < WAIT,
                "only {} of {n} frames arrived",
                got.len()
            );
            std::thread::yield_now();
        }
    }
    got
}

/// Asserts that `rx` delivers nothing over `IDLE_POLLS` polls.
fn assert_idle(rx: &mut impl RxRing, why: &str) {
    let mut out = [RxPkt::empty(); RX_BURST];
    for _ in 0..IDLE_POLLS {
        assert_eq!(rx.poll(&mut out), 0, "{why}");
        std::thread::yield_now();
    }
}

fn get(c: &core::sync::atomic::AtomicU64) -> u64 {
    ExtCounters::get(c)
}

/// Rule 1. Frames come back in the order sent, whole, with `rx_ts` non-decreasing across polls,
/// and `rx_pkts` counts them.
pub fn arrival_order<H: Harness>() {
    let mut q = open::<H>(64, 64);
    let sent: Vec<Vec<u8>> = (0..40)
        .map(|i| test_frame(q.dst, i, (i as usize % 7) * 37))
        .collect();
    for f in &sent {
        send_ok(&mut q.tx, f);
    }
    let mut last = Nanos(0);
    let mut next = 0;
    while next < sent.len() {
        let mut more = poll_n(&mut q.rx, 1);
        // Drain whatever else is ready so bursts of several frames are checked too.
        let mut out = [RxPkt::empty(); RX_BURST];
        let k = q.rx.poll(&mut out);
        more.extend_from_slice(&out[..k]);
        for p in &more {
            assert!(p.rx_ts() >= last, "rule 1: rx_ts went backwards");
            last = p.rx_ts();
            let b = q.rx.bytes(p);
            assert_eq!(b.len(), usize::from(p.len()));
            let want = frame::parse(&sent[next]).expect("sent frame").payload;
            let (seq, payload) = payload_seq(b);
            assert_eq!(seq, next as u32, "rule 1: frames out of arrival order");
            assert_eq!(payload, want, "frame {next} arrived changed");
            assert_eq!(
                frame::parse(b).expect("parse").hdr.dst.port,
                q.dst.port(),
                "destination port"
            );
            next += 1;
        }
        q.rx.release(more.len());
    }
    assert_eq!(get(&q.rx.counters().rx_pkts), 40, "rx_pkts");
    assert_eq!(get(&q.tx.counters().tx_pkts), 40, "tx_pkts");
    assert!(!q.rx.counters().fatal() && !q.tx.counters().fatal());
    let _ = q.nic.caps();
}

/// Rule 2. A frame over `MAX_FRAME_BYTES` or not fast-path is dropped and counted in
/// `tx_drop`, `send` still returns `Ok`, nothing arrives for it, and the queue keeps working.
pub fn errors_are_counters<H: Harness>() {
    let mut q = open::<H>(16, 16);
    let good = test_frame(q.dst, 7, 10);
    let mut vlan = good.clone();
    vlan[12..14].copy_from_slice(&[0x81, 0x00]);
    let bad: [&[u8]; 4] = [&[0u8; MAX_FRAME_BYTES + 1], &[0u8; 10], &vlan, &[]];
    for (i, f) in bad.iter().enumerate() {
        assert_eq!(q.tx.send(f), Ok(()), "rule 2: bad frame {i} returned Err");
    }
    assert_eq!(get(&q.tx.ext_counters().tx_drop), 4, "tx_drop");
    assert_eq!(
        get(&q.tx.counters().tx_pkts),
        0,
        "a dropped frame counted as sent"
    );
    send_ok(&mut q.tx, &good);
    let p = poll_n(&mut q.rx, 1)[0];
    assert_eq!(
        payload_seq(q.rx.bytes(&p)).0,
        7,
        "only the good frame arrives"
    );
    q.rx.release(1);
    assert_idle(&mut q.rx, "a dropped frame arrived");
    assert!(
        !q.rx.counters().fatal() && !q.tx.counters().fatal(),
        "fatal"
    );
}

/// Rule 3. Without reaping, every `send` is `Ok` (counted in `tx_pkts`) or `TxFull` (counted in
/// `tx_full`); exactly the `Ok` frames arrive, whole; `reap` accounts for every sent frame. A
/// frame of the largest size arrives whole too.
pub fn whole_frame_or_full<H: Harness>() {
    let mut q = open::<H>(64, 4);
    let (mut ok, mut full) = (Vec::new(), 0u64);
    for i in 0..12u32 {
        let f = test_frame(q.dst, i, 300);
        match q.tx.send(&f) {
            Ok(()) => ok.push(i),
            Err(TxFull) => full += 1,
        }
    }
    assert_eq!(get(&q.tx.counters().tx_pkts), ok.len() as u64, "tx_pkts");
    assert_eq!(get(&q.tx.counters().tx_full), full, "rule 3: tx_full");
    let mut reaped = q.tx.reap();
    let big = test_frame(q.dst, 99, MAX_PAYLOAD - 4);
    assert_eq!(big.len(), MAX_FRAME_BYTES);
    send_ok(&mut q.tx, &big);
    reaped += q.tx.reap();
    assert_eq!(
        reaped as u64,
        ok.len() as u64 + 1,
        "reap counts every sent frame"
    );
    let got = poll_n(&mut q.rx, ok.len() + 1);
    for (p, &want) in got.iter().zip(ok.iter().chain([&99])) {
        let b = q.rx.bytes(p);
        let (seq, payload) = payload_seq(b);
        assert_eq!(seq, want, "rule 3: a TxFull frame arrived, or one was lost");
        let len = if want == 99 { MAX_PAYLOAD } else { 304 };
        assert_eq!(payload.len(), len, "rule 3: frame {want} arrived partial");
    }
    q.rx.release(got.len());
    assert_idle(&mut q.rx, "rule 3: a frame refused with TxFull arrived");
}

/// `release(n)` frees the oldest `n` unreleased frames; a queue with every buffer held returns
/// no frames, and each frame it could not take either arrives after a release or is counted in
/// `rx_discard`; releasing more than is held frees everything.
pub fn release_order<H: Harness>() {
    let mut q = open::<H>(16, 64);
    for i in 0..20 {
        send_ok(&mut q.tx, &test_frame(q.dst, i, 20));
    }
    let held = poll_n(&mut q.rx, 16);
    assert_idle(&mut q.rx, "poll returned a frame with every buffer held");
    for (i, p) in held.iter().enumerate() {
        assert_eq!(payload_seq(q.rx.bytes(p)).0, i as u32);
    }
    q.rx.release(1);
    assert!(
        q.rx.bytes(&held[0]).is_empty(),
        "released frame 0 still readable"
    );
    assert_eq!(
        payload_seq(q.rx.bytes(&held[1])).0,
        1,
        "frame 1 lost by release(1)"
    );
    q.rx.release(3);
    assert!(held[..4].iter().all(|p| q.rx.bytes(p).is_empty()));
    assert_eq!(payload_seq(q.rx.bytes(&held[4])).0, 4);
    let mut rest = Vec::new();
    let mut out = [RxPkt::empty(); RX_BURST];
    let t = Instant::now();
    while rest.len() as u64 + get(&q.rx.counters().rx_discard) < 4 {
        let k = q.rx.poll(&mut out);
        rest.extend_from_slice(&out[..k]);
        assert!(
            t.elapsed() < WAIT,
            "a frame sent to a full queue was neither held nor counted"
        );
        std::thread::yield_now();
    }
    for (i, p) in rest.iter().enumerate() {
        assert_eq!(
            payload_seq(q.rx.bytes(p)).0,
            16 + i as u32,
            "held-back frames in order"
        );
    }
    q.rx.release(1000);
    assert!(held.iter().chain(&rest).all(|p| q.rx.bytes(p).is_empty()));
    assert_eq!(
        get(&q.rx.counters().rx_pkts),
        16 + rest.len() as u64,
        "rx_pkts"
    );
}

/// `bytes` returns `&[]` for every descriptor the queue did not produce or already released,
/// including an exact copy of a live descriptor kept past its release, one whose slot has since
/// been reused, and a live descriptor of another queue.
pub fn forged_descriptors<H: Harness>() {
    let mut q = open::<H>(16, 64);
    let mut rx2 = q.nic.rx_ring(&H::bind(1)).expect("second rx_ring");
    let dst2 = H::dest(&rx2);
    for i in 0..3 {
        send_ok(&mut q.tx, &test_frame(q.dst, i, 50));
    }
    send_ok(&mut q.tx, &test_frame(dst2, 100, 50));
    let live = poll_n(&mut q.rx, 3);
    let other = poll_n(&mut rx2, 1)[0];
    let p = live[0];
    let real = q.rx.bytes(&p).to_vec();
    assert_eq!(payload_seq(&real).0, 0);

    let local = [0xAAu8; 2048];
    let local_ptr = NonNull::from(&local[0]);
    let forged = |data, len, buf_id| RxPkt::new(data, len, p.flags(), buf_id, p.rx_ts());
    let cases = [
        ("empty()", RxPkt::empty()),
        ("len + 1", forged(p.data(), p.len() + 1, p.buf_id())),
        ("len - 1", forged(p.data(), p.len() - 1, p.buf_id())),
        ("len max", forged(p.data(), u16::MAX, p.buf_id())),
        ("foreign data", forged(local_ptr, p.len(), p.buf_id())),
        (
            "next buf_id",
            forged(p.data(), p.len(), live[2].buf_id().wrapping_add(1)),
        ),
        (
            "prev buf_id",
            forged(p.data(), p.len(), p.buf_id().wrapping_sub(1)),
        ),
        ("other queue's", other),
        (
            "other queue's fields",
            forged(other.data(), other.len(), p.buf_id()),
        ),
    ];
    for (name, f) in &cases {
        assert!(
            q.rx.bytes(f).is_empty(),
            "forged descriptor ({name}) read bytes"
        );
    }
    let copy = RxPkt::new(p.data(), p.len(), RxFlags(0xFFFF), p.buf_id(), Nanos(0));
    assert_eq!(
        q.rx.bytes(&copy),
        real,
        "a copy of a live descriptor reads its frame"
    );
    assert_eq!(
        payload_seq(rx2.bytes(&other)).0,
        100,
        "the other queue's frame"
    );

    q.rx.release(3);
    assert!(q.rx.bytes(&copy).is_empty(), "copy read past release");
    assert!(live.iter().all(|p| q.rx.bytes(p).is_empty()));
    // Fill every buffer again, so the copy's slot now holds a live frame.
    for i in 0..16 {
        send_ok(&mut q.tx, &test_frame(q.dst, 200 + i, 50));
    }
    let again = poll_n(&mut q.rx, 16);
    assert!(again.iter().all(|p| !q.rx.bytes(p).is_empty()));
    assert!(
        q.rx.bytes(&copy).is_empty(),
        "stale copy read a reused slot"
    );
    let a = again[0];
    let with = |data, buf_id| RxPkt::new(data, a.len(), a.flags(), buf_id, a.rx_ts());
    assert!(q.rx.bytes(&with(local_ptr, a.buf_id())).is_empty());
    // With every buffer held, the next id a full ring would hand out names the oldest live
    // buffer's slot on a ring indexed by id: a forged "future" id must not read that frame.
    let future = with(a.data(), again[15].buf_id().wrapping_add(1));
    assert!(
        q.rx.bytes(&future).is_empty(),
        "a not-yet-produced buf_id read a live frame"
    );
}

/// Every check, in order.
pub fn run_all<H: Harness>() {
    arrival_order::<H>();
    errors_are_counters::<H>();
    whole_frame_or_full::<H>();
    release_order::<H>();
    forged_descriptors::<H>();
}
