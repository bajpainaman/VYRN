//! Simplex on Commonware: proposal, votes, certificates, view changes, silence detection
//! (spec/11-build.md §1.3).
//!
//! The crate orders blocks and never calls the matching engine (11 §1.4, 07 "BFT finalizes the
//! order, not the state"). Its boundary is four contracts, each written before the code behind it:
//!
//! | Contract | Type | Spec |
//! |---|---|---|
//! | What the block source hands in | [`BlockSource`], [`Verdict`]; [`LogSource`] over `vyrn-log` | 07 §6.4, §8.2 |
//! | What a proposal commits to | [`Proposal`] (`REP_Proposal`, 85 bytes) | 07 §6.3 |
//! | Who may vote | [`Committee`] (the voters of `REP_Membership`) | 07 §13.1, 01 §14.4 |
//! | What a certificate proves, checked offline | [`FinalityCert`], [`verify_finality_cert`] | 07 §6.5 |
//!
//! [`voter`] wires these into `commonware-consensus` Simplex (07 §6.3) for one voter, and
//! [`silence`] detects a silent sequencer (07 §9.1); [`tail`] signs what each voter holds and
//! computes the prefix and seal of a deposed tenure (07 §9.2–9.5). The sequencer is never a voter: a
//! [`Committee`] refuses a `seq_key` among its voters, and [`voter::config`] refuses a key that
//! is not a voter (01 §14.4).
#![forbid(unsafe_code)]

pub mod cert;
pub mod membership;
pub mod proposal;
pub mod silence;
pub mod source;
pub mod tail;
pub mod voter;

pub use cert::{CertErr, FinalityCert, NAMESPACE, verify_finality_cert};
pub use membership::{Committee, CommitteeErr, VoterOrder};
pub use proposal::{Proposal, ProposalErr, ProposalKind};
pub use source::{BlockSource, Genesis, LogSource, Verdict};
pub use tail::{Prefix, Reporter, SealExt, Silence, Tail, TailErr, TailReport};

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod tests;
