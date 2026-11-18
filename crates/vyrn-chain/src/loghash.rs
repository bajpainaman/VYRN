//! The log hash chain (09 §9.2): one BLAKE3 link per chain block over its three roots.
//!
//! ```text
//! log_hash(H) = BLAKE3(derive_key("vyrn v1 log",
//!                 log_hash(H − 1) ‖ books_root(H) ‖ items_root(H) ‖ excl_root(H)))
//! log_hash(0) = genesis_hash
//! ```
//!
//! The roots come from the `ChainHeader` (09 §4.3); computing them is the block builder's job.
//! Two copies of the log are identical up to H exactly when their `log_hash(H)` agree.

use vyrn_crypto::derive_key;
use vyrn_crypto::hash::hash;
use vyrn_types::{Hash, Height};

/// The `derive_key` context (09 §17.3).
pub const LOG_CONTEXT: &str = "vyrn v1 log";

/// The three roots one chain block adds to the log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Roots {
    /// Merkle root over the block's `BookEntry`s.
    pub books_root: Hash,
    /// Merkle root over its items.
    pub items_root: Hash,
    /// Merkle root over its exclusion lists.
    pub excl_root: Hash,
}

/// `log_hash(H)` from `log_hash(H − 1)` and block H's roots.
pub fn link(prev: &Hash, r: &Roots) -> Hash {
    let mut m = [0u8; 128];
    for (dst, src) in
        m.as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip([prev, &r.books_root, &r.items_root, &r.excl_root])
    {
        *dst = src.0;
    }
    hash(&derive_key(LOG_CONTEXT, &m))
}

/// The running head of the chain: height and `log_hash`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogChain {
    height: Height,
    head: Hash,
}

/// A header's `log_hash` is not the one its predecessor and roots give, or its height is not
/// the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// `height ≠ head height + 1`.
    #[error("chain height {got:?} does not follow {head:?}")]
    Height {
        /// The chain's height.
        head: Height,
        /// The block's height.
        got: Height,
    },
    /// The block's `log_hash` differs from the recomputed link (voter check 7, 09 §4.3).
    #[error("log_hash mismatch at height {0:?}")]
    Mismatch(Height),
}

impl LogChain {
    /// At height 0 with `log_hash(0) = genesis_hash`.
    pub fn genesis(genesis_hash: Hash) -> Self {
        Self {
            height: Height(0),
            head: genesis_hash,
        }
    }

    /// Resumes from a known `(H, log_hash(H))`, such as a `HandoffRecord` or a snapshot.
    pub fn resume(height: Height, log_hash: Hash) -> Self {
        Self {
            height,
            head: log_hash,
        }
    }

    /// The current height.
    pub fn height(&self) -> Height {
        self.height
    }

    /// `log_hash(height)`.
    pub fn head(&self) -> Hash {
        self.head
    }

    /// What `log_hash` block `height() + 1` with `roots` must carry. Does not advance.
    pub fn next(&self, roots: &Roots) -> Hash {
        link(&self.head, roots)
    }

    /// Checks block `height` against its claimed `log_hash` and advances on success.
    pub fn append(
        &mut self,
        height: Height,
        roots: &Roots,
        log_hash: &Hash,
    ) -> Result<(), LogError> {
        if Some(height.0) != self.height.0.checked_add(1) {
            return Err(LogError::Height {
                head: self.height,
                got: height,
            });
        }
        let want = self.next(roots);
        if want != *log_hash {
            return Err(LogError::Mismatch(height));
        }
        self.height = height;
        self.head = want;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn roots(i: u8) -> Roots {
        Roots {
            books_root: Hash([i; 32]),
            items_root: Hash([i.wrapping_add(1); 32]),
            excl_root: Hash([i.wrapping_add(2); 32]),
        }
    }

    /// `b3sum --derive-key "vyrn v1 log" --raw` over `[0]*32 ‖ [1]*32 ‖ [2]*32 ‖ [3]*32`, then
    /// `b3sum` over that (b3sum 1.8.7).
    #[test]
    fn link_matches_b3sum() {
        let h = link(&Hash([0; 32]), &roots(1));
        let hex: String = h.0.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, LINK);
    }
    const LINK: &str = "9e509222841251d480c82aaa4c0fe10bdeeb36887a876a51f99d37715dccb8ad";

    #[test]
    fn chain_checks_height_and_every_root() {
        let g = Hash([9; 32]);
        let mut c = LogChain::genesis(g);
        let h1 = c.next(&roots(1));
        c.append(Height(1), &roots(1), &h1).unwrap();
        assert_eq!((c.height(), c.head()), (Height(1), h1));
        let h2 = c.next(&roots(2));
        // Skipping a height or changing any one root is refused and leaves the head alone.
        assert!(matches!(
            c.append(Height(3), &roots(2), &h2),
            Err(LogError::Height { .. })
        ));
        for r in [
            Roots {
                books_root: Hash([0; 32]),
                ..roots(2)
            },
            Roots {
                items_root: Hash([0; 32]),
                ..roots(2)
            },
            Roots {
                excl_root: Hash([0; 32]),
                ..roots(2)
            },
        ] {
            assert_eq!(
                c.append(Height(2), &r, &h2),
                Err(LogError::Mismatch(Height(2)))
            );
        }
        assert_eq!(c.head(), h1);
        c.append(Height(2), &roots(2), &h2).unwrap();
        // The order of the inputs matters: prev is first.
        assert_ne!(
            link(
                &roots(2).books_root,
                &Roots {
                    books_root: h1,
                    ..roots(2)
                }
            ),
            h2
        );
        assert_eq!(LogChain::resume(Height(2), h2), c);
    }
}
