//! A reject: a 01 §6.5 reason and its u32 detail (04 §8, 10 §3.1).

use vyrn_types::RejectReason;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reject {
    pub reason: RejectReason,
    pub detail: u32,
}

#[inline(always)]
pub(crate) const fn rej(reason: RejectReason, detail: u32) -> Reject {
    Reject { reason, detail }
}
