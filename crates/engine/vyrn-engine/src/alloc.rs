//! `vyrn-engine::alloc` (UNSAFE.toml): the sealing allocator (`INV-NOALLOC`, 11 §3.5). Every
//! `unsafe` block needs a `// SAFETY:` comment. A binary installs it with
//! `#[global_allocator] static A: SealingAlloc = SealingAlloc;`.
//!
//! State is per thread: [`seal`] marks the calling thread, so control and consensus threads keep
//! allocating. On a sealed thread `alloc`, `alloc_zeroed`, `realloc` and `dealloc` abort the
//! process (the fixed fd-2 message of 11 §3.5 needs `libc`, which 11 §2.2 does not allow here:
//! PR follow-up). [`seal_counting`] is the test and `vyrn-sim` form: it counts instead.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const OPEN: u8 = 0;
const SEALED: u8 = 1;
const COUNTING: u8 = 2;

thread_local! {
    // const init: reading these never allocates and registers no destructor.
    static STATE: Cell<u8> = const { Cell::new(OPEN) };
    static COUNT: Cell<u64> = const { Cell::new(0) };
}

/// The global allocator of every production binary.
pub struct SealingAlloc;

#[inline]
fn check() {
    match STATE.try_with(Cell::get).unwrap_or(OPEN) {
        SEALED => std::process::abort(),
        COUNTING => {
            let _ = COUNT.try_with(|c| c.set(c.get().saturating_add(1)));
        }
        _ => {}
    }
}

// SAFETY: every method checks the thread's state and then forwards its arguments unchanged to
// `System`, so `System`'s guarantees are this allocator's.
unsafe impl GlobalAlloc for SealingAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        check();
        // SAFETY: the caller's `alloc` contract, forwarded unchanged.
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        check();
        // SAFETY: the caller's `alloc_zeroed` contract, forwarded unchanged.
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        check();
        // SAFETY: `p` came from `System` through this allocator with layout `l`.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        check();
        // SAFETY: `p` came from `System` through this allocator with layout `l`.
        unsafe { System.realloc(p, l, new_size) }
    }
}

/// Called by each pinned core as the last step of its setup: from now on an allocation or a
/// free on this thread aborts.
pub fn seal() {
    let _ = STATE.try_with(|s| s.set(SEALED));
}

/// Test and `vyrn-sim` form of [`seal`]: allocations on this thread are counted, not fatal.
pub fn seal_counting() {
    let _ = STATE.try_with(|s| s.set(COUNTING));
}

/// Ends a counting seal (tests read [`violations`] first, then unseal to report).
pub fn unseal() {
    let _ = STATE.try_with(|s| s.set(OPEN));
}

/// Allocator calls counted on this thread while it was sealed with [`seal_counting`].
pub fn violations() -> u64 {
    COUNT.try_with(Cell::get).unwrap_or(0)
}
