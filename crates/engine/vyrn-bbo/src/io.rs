//! The BBO core's ring and line handles (05 §4.1, §8.2) and the result of one loop pass.

use vyrn_cut::{
    BboFloor, Consumer, ENG_FILL_RING, ENG_FWD_RING, ENG_STEP_LOG, ENG_TX_RING, HalfCut, Line32,
    Line64, Producer, Ring, STEP_LOG_READERS, SnapshotLine, Visibility,
};
use vyrn_types::StepId;

use crate::ENG_CONTROL_RING;

/// The BBO core's end of lane `l`'s `FwdRing`.
pub type FwdCons<'a, V> = Consumer<'a, Line64, ENG_FWD_RING, 1, V>;
/// The BBO core's end of lane `l`'s `FillRing`.
pub type FillProd<'a, V> = Producer<'a, Line32, ENG_FILL_RING, 1, V>;
/// The BBO core's end of the `StepLog`.
pub type StepLogProd<'a, V> = Producer<'a, Line64, ENG_STEP_LOG, STEP_LOG_READERS, V>;
/// The BBO core's end of one fill TX core's `TxRing`.
pub type TxProd<'a, V> = Producer<'a, Line64, ENG_TX_RING, 1, V>;
/// The control ring (05 §4.1): control role (core 0) → BBO core, one [`crate::ControlCmd`]
/// per line.
pub type ControlRing<V> = Ring<Line64, ENG_CONTROL_RING, 1, V>;
/// The BBO core's end of the control ring.
pub type ControlCons<'a, V> = Consumer<'a, Line64, ENG_CONTROL_RING, 1, V>;

/// Everything one BBO core reads and writes. `fwd` and `fill` are indexed by lane; `tx[0]` is
/// fill TX core A (sessions of lanes 0–24), `tx[1]` is B (lanes 25–48).
pub struct Ports<'p, 'a, V: Visibility> {
    pub half_a: &'p HalfCut<V>,
    pub half_b: &'p HalfCut<V>,
    pub fwd: &'p mut [FwdCons<'a, V>],
    pub control: &'p mut ControlCons<'a, V>,
    pub fill: &'p mut [FillProd<'a, V>],
    pub step_log: &'p mut StepLogProd<'a, V>,
    pub tx: &'p mut [TxProd<'a, V>],
    pub snapshot: &'p SnapshotLine<V>,
    pub floor: &'p BboFloor<V>,
}

/// The result of one [`crate::Bbo::poll`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    /// Step `s` was decided and fully published.
    Step(StepId),
    /// Nothing to do: no source, no control command, no new cut.
    Idle,
    /// A ring was full. The decided step stays held and the next poll resumes publishing it;
    /// nothing is decided again (`INV-ENG-6`).
    Stalled,
    /// An engine fault (05 §14.3): the caller fail-stops the sequencer.
    Fault,
}
