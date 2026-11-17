//! Atomics, fences and the slot cell. tests/loom.rs compiles `src/` as a module of its own test
//! crate (`cfg(all(loom, test))`), which swaps in loom's types, so the loom models of
//! spec/11-build.md §6.1 check the production code while loom stays a dev-dependency (§2.2).
//! Every other build uses core's.

pub use core::sync::atomic::Ordering;

#[cfg(all(loom, test))]
pub(crate) use loom::sync::atomic::{AtomicU32, AtomicU64, fence};

#[cfg(not(all(loom, test)))]
pub(crate) use core::sync::atomic::{AtomicU32, AtomicU64, fence};

#[cfg(all(loom, test))]
pub(crate) use loom::cell::UnsafeCell;

/// `core::cell::UnsafeCell` with loom's closure API, so `ring` has one code path for both.
#[cfg(not(all(loom, test)))]
#[derive(Debug)]
pub(crate) struct UnsafeCell<T>(core::cell::UnsafeCell<T>);

#[cfg(not(all(loom, test)))]
impl<T> UnsafeCell<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(core::cell::UnsafeCell::new(value))
    }

    #[inline(always)]
    pub(crate) fn with<R>(&self, f: impl FnOnce(*const T) -> R) -> R {
        f(self.0.get())
    }

    #[inline(always)]
    pub(crate) fn with_mut<R>(&self, f: impl FnOnce(*mut T) -> R) -> R {
        f(self.0.get())
    }
}
