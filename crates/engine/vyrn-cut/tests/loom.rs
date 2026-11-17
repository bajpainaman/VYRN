//! loom models (spec/11-build.md §6.1, §3.9 rule 5): the ring, the seqlock, the cut publication
//! and the pool primitives, every interleaving up to preemption bound 3, on the production code
//! with loom's atomics. Run with `RUSTFLAGS="--cfg loom" cargo test -p vyrn-cut --test loom
//! --release`.
#![cfg(loom)]
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use loom::sync::atomic::AtomicU32;
use loom::sync::atomic::Ordering::Relaxed;
use loom::thread;
// The crate's source as a module of this test crate, so `cfg(all(loom, test))` in src/sync.rs
// selects loom's atomics for exactly this build (11 §2.2: loom is a test dependency only).
#[path = "../src/lib.rs"]
#[allow(dead_code, unused_imports)]
mod vyrn_cut;

use vyrn_cut::*;
use vyrn_types::{LaneId, LaneSeq, StepId, Tick};

fn model(f: impl Fn() + Sync + Send + 'static) {
    let mut b = loom::model::Builder::new();
    b.preemption_bound = Some(3);
    b.check(f);
}

/// loom has no scoped threads; a model's ring lives for the rest of the test process.
fn leak<T>(v: T) -> &'static mut T {
    Box::leak(Box::new(v))
}

#[test]
fn spsc_ring_wraps_without_loss_or_reorder() {
    model(|| {
        let ring = leak(Ring::<[u64; 2], 2, 1, Hw>::new(&Hw));
        let (mut p, [mut c]) = ring.split().unwrap();
        let t = thread::spawn(move || {
            let mut k = 0u64;
            while k < 3 {
                if p.push(&Hw, [k, !k]).is_ok() {
                    k += 1;
                } else {
                    thread::yield_now();
                }
            }
        });
        let mut want = 0u64;
        while want < 3 {
            match c.pop(&Hw) {
                Some([a, b]) => {
                    assert_eq!((a, b), (want, !want));
                    want += 1;
                }
                None => thread::yield_now(),
            }
        }
        t.join().unwrap();
    });
}

#[test]
fn broadcast_ring_waits_for_the_slowest_consumer() {
    model(|| {
        let ring = leak(Ring::<u64, 1, 2, Hw>::new(&Hw));
        let (mut p, cs) = ring.split().unwrap();
        // Bounded attempts, no spinning (three spinning threads exceed loom's branch limit). A
        // rewrite of the one slot before both consumers read it is a race loom reports.
        let ts = cs.map(|mut c| {
            thread::spawn(move || {
                let mut want = 0u64;
                for _ in 0..2 {
                    if let Some(v) = c.pop(&Hw) {
                        assert_eq!(v, want, "lost or reordered");
                        want += 1;
                    }
                }
                want
            })
        });
        assert_eq!(p.push(&Hw, 0), Ok(()));
        let second = p.push(&Hw, 1).is_ok();
        let got = ts.map(|t| t.join().unwrap());
        if second {
            assert!(
                got.iter().all(|n| *n >= 1),
                "slot reused before every consumer read it"
            );
        }
    });
}

#[test]
fn snapshot_seqlock_never_tears() {
    let snap = |k: u64| Snapshot {
        version: k,
        bid: Tick(u32::try_from(k).unwrap()),
        ask: Tick(u32::try_from(k + 1).unwrap()),
        done_step: StepId(k),
        ..Default::default()
    };
    model(move || {
        let line: &'static SnapshotLine<Hw> = leak(SnapshotLine::new(&Hw, &snap(0)));
        let t = thread::spawn(move || {
            line.publish(&Hw, &snap(1));
            line.publish(&Hw, &snap(2));
        });
        let mut last = 0;
        for _ in 0..2 {
            if let Some(r) = line.try_read(&Hw) {
                assert_eq!(r, snap(r.version), "torn read");
                assert!(r.version >= last, "went back");
                last = r.version;
            }
        }
        t.join().unwrap();
        assert_eq!(line.try_read(&Hw), Some(snap(2)));
    });
}

#[test]
fn half_cut_reader_sees_a_whole_newest_publication_and_never_goes_back() {
    model(|| {
        let half: &'static HalfCut<Hw> = leak(HalfCut::new(&Hw, &HalfCutVal::default()));
        let t = thread::spawn(move || {
            let mut w = CutWriter::new();
            let mut v = HalfCutVal::default();
            for k in 1..=2u64 {
                v.entries[0].seq = LaneSeq(k);
                v.entries[24].seq = LaneSeq(k * 10);
                w.publish(half, &Hw, &v).unwrap();
            }
        });
        let mut last = 0;
        for _ in 0..2 {
            if let Some((id, v)) = half.try_read_newest(&Hw) {
                assert_eq!(v.pub_id, id);
                assert_eq!(v.entries[0].seq, LaneSeq(id), "torn");
                assert_eq!(v.entries[24].seq, LaneSeq(id * 10), "torn");
                assert!(id >= last, "INV-CUT-MONO");
                last = id;
            }
        }
        t.join().unwrap();
    });
}

/// Two cores race for one token; the holder's write is seen by the next taker.
#[test]
fn pool_token_hands_writes_from_holder_to_taker() {
    model(|| {
        let tok: &'static PoolTok = leak(PoolTok::new());
        // Relaxed read-then-write: without the token's Acquire/Release the second holder can
        // read the stale 0 and the final count is 1 (INV-WRITER hand-over).
        let rec: &'static AtomicU32 = leak(AtomicU32::new(0));
        let ts = [42u8, 43].map(|lane| {
            thread::spawn(move || {
                loop {
                    match tok.try_take(LaneId(lane)) {
                        Ok(_) => break,
                        Err(_) => thread::yield_now(),
                    }
                }
                let v = rec.load(Relaxed);
                rec.store(v + 1, Relaxed);
                tok.release(LaneId(lane)).unwrap();
            })
        });
        for t in ts {
            t.join().unwrap();
        }
        assert_eq!(tok.peek(), (None, 2));
        let v = rec.load(Relaxed);
        assert_eq!(v, 2);
    });
}

#[test]
fn steal_lock_excludes() {
    model(|| {
        let lock: &'static StealLock = leak(StealLock::new());
        let n: &'static AtomicU32 = leak(AtomicU32::new(0));
        let ts = [44u8, 45].map(|core| {
            thread::spawn(move || {
                let g = loop {
                    if let Some(g) = lock.try_lock(LaneId(core)) {
                        break g;
                    }
                    thread::yield_now();
                };
                let v = n.load(Relaxed);
                n.store(v + 1, Relaxed);
                drop(g);
            })
        });
        for t in ts {
            t.join().unwrap();
        }
        let v = n.load(Relaxed);
        assert_eq!(v, 2);
    });
}

/// A sibling-segment cancel (`fetch_and`) races the owner lane's `fetch_or` of another bit and
/// the BBO core's sweep (05 §6.9): no change is lost, and the sweep sees a bit set only with the
/// slot write before it.
#[test]
fn sibling_fetch_and_against_sweep() {
    model(|| {
        let mask: &'static SegMask = leak(SegMask::new(SegMask::active_bit(0).unwrap()));
        let slot: &'static AtomicU32 = leak(AtomicU32::new(0));
        let owner = thread::spawn(move || {
            slot.store(7, Relaxed);
            mask.fetch_or(SegMask::active_bit(1).unwrap());
        });
        let sibling = thread::spawn(move || {
            mask.fetch_and_not(SegMask::active_bit(0).unwrap());
        });
        let m = mask.load();
        if m & SegMask::active_bit(1).unwrap() != 0 {
            assert_eq!(slot.load(Relaxed), 7);
        }
        owner.join().unwrap();
        sibling.join().unwrap();
        assert_eq!(mask.load(), SegMask::active_bit(1).unwrap());
    });
}
