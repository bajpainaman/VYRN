//! Epochs: the schedule, the go/no-go, the `HandoffRecord` certificate, fencing, the
//! `EpochNotice` triggers and the membership hand-off to `vyrn-consensus` (spec/08-epochs.md,
//! 11 §1.3).
//!
//! The crate decides **when** a book moves and **what proves** that it moved. It never matches,
//! never touches a NIC and never runs consensus: it takes logged records and certificates in and
//! hands out verdicts and the next epoch's [`Membership`]. Every function is a pure function of
//! its inputs, so the sequencer, every replica, every client and an auditor compute the same
//! answers (`INV-DET`).
//!
//! # Contract
//!
//! Each row is fixed before the code behind it. "Writer" makes the bytes or the record, "readers"
//! act on it, "ordering" says what must come first, and every reject is a variant of the named
//! error type.
//!
//! | Contract | Type | Writer | Readers | Ordering | Rejects | Spec |
//! |---|---|---|---|---|---|---|
//! | The schedule: slots, `home(e)`, T, holds, skips, overrides | [`Timetable`], [`Boundary`], [`ScheduleRecord`] | the log (control records) | clients, lanes, replicas, `vyrn-chain` | records apply in log order; skips and overrides ≥ `EPO_CONFIG_LEAD_S` before their boundary; a hold only before T | [`ScheduleErr`] | 08 §2.1–2.5, 09 §2 |
//! | The next epoch's configuration | [`EpoConfig`] | the control path | replicas | final ≥ `EPO_CONFIG_LEAD_S` before T, else carried forward | none: a late record is ignored | 08 §2.3 |
//! | When a lane sends `EpochNotice` | [`Notifier`], [`EpochNotice`] | each lane | sessions; replicas reproduce it | a pure function of logged `rx_ts` | none | 08 §2.4 |
//! | Readiness and the go/no-go | [`EpoReady`], [`ReadyPool`], [`EpoGo`], [`EpoHold`] | `R_{e+1}` and both new `vyrn-seq` boxes; the proposer | every voter of `R_e` | `EpoReady` from `T − EPO_PREP_LEAD_S`; the decision at `T − EPO_GO_LEAD_S` | [`GoErr`] | 08 §2.6 |
//! | The handoff certificate | [`encode_record`], [`HandoffSig`], [`HandoffCert`], [`CertBuilder`] | each voter of `R_e`, once per (book, e) ([`SignOnce`]) | `R_{e+1}`, both new `vyrn-seq` boxes, the third home, light clients | sign only after the block with S is final; persist before send | [`HandoffErr`] with an [`Action`] | 08 §5 |
//! | Verification at the new home | [`accept_cert`], [`LocalView`] | — | `R_{e+1}`, third home | checks 1–5 in order; the first failure decides | [`HandoffErr`] | 08 §5.4 |
//! | Fencing (`INV-FENCE`) | [`Fence`], [`check_next_vote`] | — | every replica and follower | from the first moment Q signatures on one record are held | [`FenceErr`] | 08 §8.2 F1, F4 |
//! | The membership hand-off | [`Membership`], [`Activation`], [`Membership::hand_off`] | `EpoConfig(e+1)` (roster) | `vyrn-consensus` (the next [`vyrn_consensus::Committee`]), `vyrn-replica`, `vyrn-chain` | only with a verified cert(e, S) | [`MembershipErr`], [`HandoffErr`] | 08 §9, 07 §13.1 |
//!
//! # Domain separation
//!
//! Every signature here is Ed25519 over a 32-byte BLAKE3 `derive_key` of
//! `genesis_hash ‖ mode ‖ body` ([`Domain`]), so a record from one deployment or mode never
//! verifies in another (08 §5.2). Contexts keep the six spaces after "vyrn" byte for byte, as
//! `vyrn-log` and `vyrn-consensus` do.
//!
//! # Conformance
//!
//! `vectors/handoff.txt` (record bytes, signing messages, certificates and verdicts) and
//! `vectors/schedule.txt` (timetables and notice sequences) are plain `key = value` lines that an
//! implementation in any language can check. The `conformance` tests rebuild both files from
//! first principles and fail on any difference; `VYRN_BLESS=1` rewrites them.
//!
//! # Not in this crate yet
//!
//! The opening auction (08 §7), the role state machines (§4) and the tail stream (§5.5) are
//! follow-ups. The spec gaps this crate had to fill are marked "Spec gap" at the point of use.
#![forbid(unsafe_code)]

mod fence;
mod handoff;
mod membership;
mod notice;
mod ready;
mod schedule;

pub use fence::{Fence, FenceErr, check_next_vote};
pub use handoff::{
    Action, CertBuilder, HANDOFF_CONTEXT, HandoffCert, HandoffErr, HandoffSig, LocalView,
    RECORD_BYTES, SignOnce, Signed, accept_cert, decode_record, encode_record, handoff_message,
    record_hash, sign_record, verify_cert,
};
pub use membership::{Activation, Membership, MembershipErr, SeqBox};
pub use notice::{EpochNotice, NoticeFlags, Notifier};
pub use ready::{EpoGo, EpoHold, EpoReady, GoErr, READY_CONTEXT, ReadyPool, SEQ_MEMBER};
pub use schedule::{
    Boundary, EpoConfig, ScheduleErr, ScheduleRecord, Timetable, default_home, slot_start,
};
pub use vyrn_types::HandoffRecord;

use vyrn_types::{Hash, Mode};

/// One epoch slot, in nanoseconds: `EPOCH_HOURS` × 3,600 s (08 §2.2).
pub const EPOCH_NS: u64 = vyrn_types::EPOCH_HOURS * 3_600 * NS_PER_S;
/// Nanoseconds per second.
pub const NS_PER_S: u64 = 1_000_000_000;
/// The `EpoConfig` of e+1 must be final this long before T (08 §2.3).
pub const EPO_CONFIG_LEAD_S: u64 = 3_600;
/// `EpoReady` and key derivation start this long before T (08 §4.9).
pub const EPO_PREP_LEAD_S: u64 = 60;
/// The go/no-go is proposed this long before T (08 §2.6).
pub const EPO_GO_LEAD_S: u64 = 10;
/// An `EpoReady` older than this at the proposal's `rx_ts` does not count (08 §2.6).
pub const EPO_READY_FRESH_MS: u64 = 3_000;
/// A node sends `EpoReady` only with a replay lag at most this (08 §2.6).
pub const EPO_READY_LAG_MS: u64 = 1;
/// A hold moves T by this much (08 §2.5).
pub const EPO_HOLD_S: u64 = 900;
/// `EpochNotice` offsets before T, largest first (08 §2.4).
pub const EPO_NOTICE_OFFSETS_S: [u64; 5] = [3_600, 600, 60, 10, 1];

/// What every signature in this crate is bound to (08 §5.2): the deployment and the mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domain {
    pub genesis_hash: Hash,
    pub mode: Mode,
}

impl Domain {
    /// `genesis_hash ‖ mode`, the prefix of every signed body.
    ///
    /// Spec gap: 08 §5.2 writes `mode` without an encoding. This crate uses one byte, 0 for BASE
    /// and 1 for CHAIN, the order 01 lists them in [Guessing].
    fn prefix(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[..32].copy_from_slice(&self.genesis_hash.0);
        out[32] = match self.mode {
            Mode::Base => 0,
            Mode::Chain => 1,
        };
        out
    }

    /// `derive_key(context, genesis_hash ‖ mode ‖ body)`: the 32 bytes that are signed.
    fn message(&self, context: &str, body: &[u8]) -> [u8; 32] {
        let mut material = Vec::with_capacity(33 + body.len());
        material.extend_from_slice(&self.prefix());
        material.extend_from_slice(body);
        vyrn_crypto::hash::derive_key(context, &material)
    }
}

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod testkit;
