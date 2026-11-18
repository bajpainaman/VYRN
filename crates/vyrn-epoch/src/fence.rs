//! Fencing, `INV-FENCE` (08 §8.2 F1 and F4).
//!
//! **F1.** From the first moment a node holds cert(e, S), it rejects every epoch-e step above S
//! and every epoch-e block above `last_height`. Each rejection is counted and alarmed; a signed
//! one is evidence (09). Frames and blocks of other epochs pass this fence: each epoch has its
//! own.
//!
//! **F4.** A node of `R_{e+1}` votes on no epoch-(e+1) block that holds a step before it has
//! verified cert(e, S). Before that it votes only on window blocks ([`check_next_vote`]).

use thiserror::Error;
use vyrn_types::{Epoch, HandoffRecord, Height, StepId};

/// Why a frame, block or vote is fenced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FenceErr {
    #[error("epoch {epoch:?} step {got:?} is above the certified S = {last:?} (F1)")]
    Step {
        epoch: Epoch,
        got: StepId,
        last: StepId,
    },
    #[error("epoch {epoch:?} block {got:?} is above the certified last_height {last:?} (F1)")]
    Block {
        epoch: Epoch,
        got: Height,
        last: Height,
    },
    #[error("a block with a step before cert(e, S) is verified (F4)")]
    Unarmed,
}

/// The fence of one epoch, built from its certified record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fence {
    epoch: Epoch,
    last_step: StepId,
    last_height: Height,
}

impl Fence {
    /// The fence of `record.epoch`. Build it only from a record with `Q` valid signatures.
    pub fn from_record(record: &HandoffRecord) -> Self {
        Self {
            epoch: record.epoch,
            last_step: record.last_step,
            last_height: record.last_height,
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// An order-stream frame of `epoch` that carries `step`.
    pub fn check_step(&self, epoch: Epoch, step: StepId) -> Result<(), FenceErr> {
        if epoch == self.epoch && step > self.last_step {
            return Err(FenceErr::Step {
                epoch,
                got: step,
                last: self.last_step,
            });
        }
        Ok(())
    }

    /// A block of `epoch` at `height`.
    pub fn check_block(&self, epoch: Epoch, height: Height) -> Result<(), FenceErr> {
        if epoch == self.epoch && height > self.last_height {
            return Err(FenceErr::Block {
                epoch,
                got: height,
                last: self.last_height,
            });
        }
        Ok(())
    }
}

/// F4: may a node of `R_{e+1}` vote on an epoch-(e+1) block? `armed` is true once the node has
/// verified cert(e, S) and persisted `armed(e+1)`; `has_step` is true for any block that is not a
/// window block.
pub fn check_next_vote(armed: bool, has_step: bool) -> Result<(), FenceErr> {
    if has_step && !armed {
        return Err(FenceErr::Unarmed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;

    #[test]
    fn f1_rejects_only_above_the_certified_end_of_its_epoch() {
        let r = testkit::record();
        let f = Fence::from_record(&r);
        let e = r.epoch;
        assert_eq!(f.check_step(e, r.last_step), Ok(()));
        assert!(matches!(
            f.check_step(e, StepId(r.last_step.0 + 1)),
            Err(FenceErr::Step { .. })
        ));
        assert_eq!(f.check_block(e, r.last_height), Ok(()));
        assert!(matches!(
            f.check_block(e, Height(r.last_height.0 + 1)),
            Err(FenceErr::Block { .. })
        ));
        // Epoch e+1 starts its own step and height counts; this fence does not apply.
        let next = Epoch(e.0 + 1);
        assert_eq!(f.check_step(next, StepId(u64::MAX)), Ok(()));
        assert_eq!(f.check_block(next, Height(u64::MAX)), Ok(()));
    }

    #[test]
    fn f4_allows_window_blocks_before_the_cert() {
        assert_eq!(check_next_vote(false, false), Ok(()));
        assert_eq!(check_next_vote(false, true), Err(FenceErr::Unarmed));
        assert_eq!(check_next_vote(true, true), Ok(()));
    }
}
