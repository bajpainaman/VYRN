//! `Dense<T, N>`: the only place engine code indexes an array (spec/11-build.md §3.7).

use crate::{AccountId, Handle, LaneId, SessionId};

/// A typed ID that indexes a dense array.
pub trait DenseId: Copy {
    fn raw(self) -> u64;
}

impl DenseId for LaneId {
    #[inline(always)]
    fn raw(self) -> u64 {
        u64::from(self.0)
    }
}

impl DenseId for SessionId {
    #[inline(always)]
    fn raw(self) -> u64 {
        u64::from(self.0)
    }
}

impl DenseId for AccountId {
    #[inline(always)]
    fn raw(self) -> u64 {
        u64::from(self.0)
    }
}

/// A handle indexes by its slot; the generation check belongs to the caller (the lane arena).
impl DenseId for Handle {
    #[inline(always)]
    fn raw(self) -> u64 {
        u64::from(self.slot())
    }
}

/// A fixed array of `N` entries, `N` a power of two. `get` range-checks; `at` masks, so LLVM can
/// prove every index in range and drop the bounds check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dense<T, const N: usize> {
    items: [T; N],
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
impl<T, const N: usize> Dense<T, N> {
    const MASK: usize = {
        assert!(N.is_power_of_two(), "Dense needs a power-of-two length");
        N - 1
    };

    pub const fn new(items: [T; N]) -> Self {
        let _ = Self::MASK;
        Self { items }
    }

    #[inline(always)]
    fn index(id: impl DenseId) -> Option<usize> {
        // Infallible on 64-bit targets (asserted in lib.rs).
        usize::try_from(id.raw()).ok()
    }

    /// The entry for `id`, or `None` if `id ≥ N`.
    #[inline(always)]
    pub fn get(&self, id: impl DenseId) -> Option<&T> {
        self.items.get(Self::index(id)?)
    }

    #[inline(always)]
    pub fn get_mut(&mut self, id: impl DenseId) -> Option<&mut T> {
        self.items.get_mut(Self::index(id)?)
    }

    /// The entry at `id mod N`. Use it only after a range check that rejects bad IDs.
    #[inline(always)]
    pub fn at(&self, id: impl DenseId) -> &T {
        &self.items[Self::index(id).unwrap_or(0) & Self::MASK]
    }

    #[inline(always)]
    pub fn at_mut(&mut self, id: impl DenseId) -> &mut T {
        &mut self.items[Self::index(id).unwrap_or(0) & Self::MASK]
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.items.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_range_checks_and_at_masks() {
        let mut d = Dense::<u32, 4>::new([10, 11, 12, 13]);
        assert_eq!(d.get(LaneId(3)), Some(&13));
        assert_eq!(d.get(LaneId(4)), None);
        assert_eq!(*d.at(SessionId(6)), 12);
        *d.at_mut(AccountId(5)) = 99;
        assert_eq!(d.get(AccountId(1)), Some(&99));
    }

    #[test]
    fn handle_indexes_by_slot_not_generation() {
        let d = Dense::<u8, 8>::new([0, 1, 2, 3, 4, 5, 6, 7]);
        let h = Handle::new(5, 200).unwrap_or_default();
        assert_eq!(d.get(h), Some(&5));
    }
}
