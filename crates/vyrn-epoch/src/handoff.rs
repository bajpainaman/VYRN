//! The `HandoffRecord`, its signatures and its certificate (08 §5).
//!
//! **What it proves.** `Q` distinct voters of `R_e` agree that epoch e of `book` ended at step S
//! (`last_step`) in the block at `last_height`, with `state_root` and `log_hash` as given, and
//! that the next sequencer signs with `next_seq_key`. Two quorums intersect in an honest voter
//! who signs once ([`SignOnce`]), so there is at most one certificate per (book, e) (§5.3).
//!
//! **Bytes.** [`encode_record`] is the 120-byte little-endian layout of §5.1. A signature is
//! Ed25519 by the voter's vote key over
//! `derive_key("vyrn      v1 handoff", genesis_hash ‖ mode ‖ record)` ([`handoff_message`]).
//! A certificate is the record followed by exactly `Q` entries `{index u8, sig [u8; 64]}`,
//! ascending by index: 315 bytes in BASE, 380 in CHAIN.
//!
//! **Who signs.** Voters of `R_e` only; never a `vyrn-seq` box (01 §14.4, `INV-EPO-7`). The
//! [`crate::Membership`] that verifies a certificate refuses sequencer keys among its voters.
//!
//! Spec gap: 08 §5.3 names a "record hash" without defining it. This crate uses BLAKE3-256 of the
//! 120 record bytes ([`record_hash`]) [Guessing]. 08 Requests to 01 item 2 (`next_epoch` at
//! offset 120) is not merged in 01 or `vyrn-types`, so the record stays 120 bytes.

use crate::Domain;
use crate::membership::Membership;
use std::collections::BTreeMap;
use thiserror::Error;
use vyrn_types::{
    BookId, Ed25519Sig, Epoch, HandoffRecord, Hash, Height, HomeCode, PubKey, StepId,
};

/// The signing context, six spaces after "vyrn" as 08 §5.2 writes it.
pub const HANDOFF_CONTEXT: &str = "vyrn      v1 handoff";
/// The encoded `HandoffRecord` (08 §5.1).
pub const RECORD_BYTES: usize = 120;
/// One certificate entry: index and signature.
const ENTRY_BYTES: usize = 1 + 64;

/// What a node does about a certificate it could not accept (08 §5.4 "Action").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Not for this node, or malformed: drop it.
    Drop,
    /// Forged or from the wrong set: drop, count and alarm.
    Alarm,
    /// This node lacks the tail: fetch it (§5.5) and check again.
    FetchTail,
    /// This node's replay is wrong: stop voting, alarm, re-sync from a snapshot (07).
    Resync,
}

/// Why a record or certificate is not accepted. [`HandoffErr::action`] maps each to §5.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum HandoffErr {
    #[error("wrong length")]
    Length,
    #[error("reserved byte is not zero")]
    Reserved,
    #[error("unknown home code {0}")]
    Home(u8),
    #[error("{got} signatures, a certificate holds exactly Q = {need}")]
    Count { got: usize, need: usize },
    #[error("signer indices are not ascending and distinct")]
    Order,
    #[error("index {0} is not a voter of R_e")]
    Unknown(u8),
    #[error("signature of voter {0} is invalid")]
    BadSig(u8),
    #[error("book, epoch or next_home is not this node's boundary")]
    NotForMe,
    #[error(
        "next_seq_key or the next epoch differs from the EpoGo this node holds, or it holds none"
    )]
    SeqKey,
    #[error("no finalized header at last_height, or its hash differs from log_hash")]
    LogHash,
    #[error("this node's replay has not executed S")]
    NoState,
    #[error("this node's state_root at S differs from the record's")]
    StateRoot,
    #[error("signature over a different record")]
    OtherRecord,
    #[error("a different record for this (book, epoch) was already signed")]
    Equivocation,
}

impl HandoffErr {
    pub fn action(self) -> Action {
        match self {
            Self::Length | Self::Reserved | Self::Home(_) | Self::NotForMe => Action::Drop,
            Self::Count { .. }
            | Self::Order
            | Self::Unknown(_)
            | Self::BadSig(_)
            | Self::OtherRecord
            | Self::Equivocation => Action::Alarm,
            Self::SeqKey | Self::LogHash | Self::NoState => Action::FetchTail,
            Self::StateRoot => Action::Resync,
        }
    }
}

/// The 120 bytes of 08 §5.1.
pub fn encode_record(r: &HandoffRecord) -> [u8; RECORD_BYTES] {
    let mut b = [0u8; RECORD_BYTES];
    b[0..2].copy_from_slice(&r.book.0.to_le_bytes());
    b[2] = r.next_home.code();
    b[4..8].copy_from_slice(&r.epoch.0.to_le_bytes());
    b[8..16].copy_from_slice(&r.last_step.0.to_le_bytes());
    b[16..24].copy_from_slice(&r.last_height.0.to_le_bytes());
    b[24..56].copy_from_slice(&r.state_root.0);
    b[56..88].copy_from_slice(&r.log_hash.0);
    b[88..120].copy_from_slice(&r.next_seq_key);
    b
}

/// Parses 08 §5.1 bytes.
pub fn decode_record(b: &[u8]) -> Result<HandoffRecord, HandoffErr> {
    let b: &[u8; RECORD_BYTES] = b.try_into().map_err(|_| HandoffErr::Length)?;
    if b[3] != 0 {
        return Err(HandoffErr::Reserved);
    }
    let arr = |at: usize| -> [u8; 32] { b[at..at + 32].try_into().unwrap_or([0; 32]) };
    let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
    Ok(HandoffRecord {
        book: BookId(u16::from_le_bytes([b[0], b[1]])),
        next_home: HomeCode::from_code(b[2]).ok_or(HandoffErr::Home(b[2]))?,
        epoch: Epoch(u32::from_le_bytes([b[4], b[5], b[6], b[7]])),
        last_step: StepId(u64_at(8)),
        last_height: Height(u64_at(16)),
        state_root: Hash(arr(24)),
        log_hash: Hash(arr(56)),
        next_seq_key: arr(88),
    })
}

/// BLAKE3-256 of the encoded record: what `HandoffSig` names and a signer persists.
pub fn record_hash(r: &HandoffRecord) -> Hash {
    vyrn_crypto::hash::hash(&encode_record(r))
}

/// The 32 bytes a voter signs (08 §5.2).
pub fn handoff_message(domain: &Domain, r: &HandoffRecord) -> [u8; 32] {
    domain.message(HANDOFF_CONTEXT, &encode_record(r))
}

/// One voter's signature on one record (08 §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandoffSig {
    pub record_hash: Hash,
    /// Voter index in `R_e`.
    pub index: u8,
    pub sig: Ed25519Sig,
}

/// Signs `r` as voter `index` with the vote-key seed. The caller must first pass
/// [`SignOnce::admit`] and persist its result (rule 4 of §5.3).
pub fn sign_record(seed: &[u8; 32], index: u8, domain: &Domain, r: &HandoffRecord) -> HandoffSig {
    HandoffSig {
        record_hash: record_hash(r),
        index,
        sig: vyrn_crypto::ed25519::sign(seed, &handoff_message(domain, r)),
    }
}

/// `HandoffCert` (08 §5.1): the record and exactly `Q` signatures, ascending by voter index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffCert {
    pub record: HandoffRecord,
    pub sigs: Vec<(u8, Ed25519Sig)>,
}

impl HandoffCert {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECORD_BYTES + ENTRY_BYTES * self.sigs.len());
        out.extend_from_slice(&encode_record(&self.record));
        for (i, sig) in &self.sigs {
            out.push(*i);
            out.extend_from_slice(sig);
        }
        out
    }

    /// Parses a certificate of `quorum` signatures. Structure only; [`verify_cert`] decides.
    pub fn decode(bytes: &[u8], quorum: usize) -> Result<Self, HandoffErr> {
        if bytes.len() != RECORD_BYTES + quorum * ENTRY_BYTES {
            return Err(HandoffErr::Length);
        }
        let record = decode_record(&bytes[..RECORD_BYTES])?;
        let sigs = bytes[RECORD_BYTES..]
            .as_chunks::<ENTRY_BYTES>()
            .0
            .iter()
            .map(|e| (e[0], e[1..].try_into().unwrap_or([0; 64])))
            .collect();
        Ok(Self { record, sigs })
    }
}

/// Check 1 of 08 §5.4: exactly `Q` ascending, distinct voters of `old` (`R_e`), each signature
/// valid under its vote key.
pub fn verify_cert(
    cert: &HandoffCert,
    domain: &Domain,
    old: &Membership,
) -> Result<(), HandoffErr> {
    let committee = old.committee();
    let need = committee.quorum();
    if cert.sigs.len() != need {
        return Err(HandoffErr::Count {
            got: cert.sigs.len(),
            need,
        });
    }
    if cert.sigs.windows(2).any(|w| w[0].0 >= w[1].0) {
        return Err(HandoffErr::Order);
    }
    let msg = handoff_message(domain, &cert.record);
    for (i, sig) in &cert.sigs {
        let key = committee.voter(*i).ok_or(HandoffErr::Unknown(*i))?;
        if !vyrn_crypto::ed25519::verify(key, &msg, sig) {
            return Err(HandoffErr::BadSig(*i));
        }
    }
    Ok(())
}

/// What a node of `R_{e+1}` or the third home holds from its own replay (08 §5.4 checks 2–5).
pub trait LocalView {
    /// The book this node replays.
    fn book(&self) -> BookId;
    /// The boundary's target home, from this node's [`crate::Timetable`].
    fn next_home(&self) -> HomeCode;
    /// `(next_epoch, next_seq_key)` of the final `EpoGo` in this node's replay of epoch e, if it
    /// holds one.
    fn go(&self) -> Option<(Epoch, PubKey)>;
    /// The header hash at `height`, if this node holds that block and its finality certificate.
    fn final_header_hash(&self, height: Height) -> Option<Hash>;
    /// This node's `state_root` after step `s`, if its replay has executed `s`.
    fn state_root(&self, s: StepId) -> Option<Hash>;
}

/// 08 §5.4 in order; the first failing check decides. `old` is `R_e`.
pub fn accept_cert(
    cert: &HandoffCert,
    domain: &Domain,
    old: &Membership,
    local: &impl LocalView,
) -> Result<(), HandoffErr> {
    verify_cert(cert, domain, old)?;
    let r = &cert.record;
    if r.book != local.book() || r.epoch != old.epoch() || r.next_home != local.next_home() {
        return Err(HandoffErr::NotForMe);
    }
    if local.go().map(|(_, key)| key) != Some(r.next_seq_key) {
        return Err(HandoffErr::SeqKey);
    }
    if local.final_header_hash(r.last_height) != Some(r.log_hash) {
        return Err(HandoffErr::LogHash);
    }
    match local.state_root(r.last_step) {
        None => Err(HandoffErr::NoState),
        Some(root) if root != r.state_root => Err(HandoffErr::StateRoot),
        Some(_) => Ok(()),
    }
}

/// Aggregates `HandoffSig`s on one record into a certificate on receipt (08 §5.3: "nobody needs
/// to aggregate first").
#[derive(Clone, Debug)]
pub struct CertBuilder {
    record: HandoffRecord,
    hash: Hash,
    msg: [u8; 32],
    sigs: BTreeMap<u8, Ed25519Sig>,
}

impl CertBuilder {
    pub fn new(record: HandoffRecord, domain: &Domain) -> Self {
        Self {
            hash: record_hash(&record),
            msg: handoff_message(domain, &record),
            record,
            sigs: BTreeMap::new(),
        }
    }

    /// Adds one signature after checking it against `old` (`R_e`). A signature over another
    /// record is [`HandoffErr::OtherRecord`]: keep it as evidence (09).
    pub fn add(&mut self, sig: &HandoffSig, old: &Membership) -> Result<(), HandoffErr> {
        if sig.record_hash != self.hash {
            return Err(HandoffErr::OtherRecord);
        }
        let key = old
            .committee()
            .voter(sig.index)
            .ok_or(HandoffErr::Unknown(sig.index))?;
        if !vyrn_crypto::ed25519::verify(key, &self.msg, &sig.sig) {
            return Err(HandoffErr::BadSig(sig.index));
        }
        self.sigs.insert(sig.index, sig.sig);
        Ok(())
    }

    /// The certificate once `Q` signatures are held: the lowest `Q` indices.
    pub fn cert(&self, quorum: usize) -> Option<HandoffCert> {
        (self.sigs.len() >= quorum).then(|| HandoffCert {
            record: self.record,
            sigs: self
                .sigs
                .iter()
                .take(quorum)
                .map(|(i, s)| (*i, *s))
                .collect(),
        })
    }
}

/// The result of [`SignOnce::admit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signed {
    /// First record for this (book, epoch): persist and fsync it, then sign and send.
    Fresh,
    /// The same record again: re-send the signature already made.
    Repeat,
}

/// Rule 4 of 08 §5.3 and F2: one record per (book, epoch). The caller persists every `Fresh`
/// admission before it sends a signature, and rebuilds this from that store on restart.
#[derive(Clone, Debug, Default)]
pub struct SignOnce {
    signed: BTreeMap<(BookId, Epoch), Hash>,
}

impl SignOnce {
    /// Rebuilds the guard from persisted `(book, epoch, record hash)` entries.
    pub fn from_persisted(entries: impl IntoIterator<Item = (BookId, Epoch, Hash)>) -> Self {
        Self {
            signed: entries.into_iter().map(|(b, e, h)| ((b, e), h)).collect(),
        }
    }

    pub fn admit(&mut self, r: &HandoffRecord) -> Result<Signed, HandoffErr> {
        let hash = record_hash(r);
        match self.signed.get(&(r.book, r.epoch)) {
            Some(h) if *h == hash => Ok(Signed::Repeat),
            Some(_) => Err(HandoffErr::Equivocation),
            None => {
                self.signed.insert((r.book, r.epoch), hash);
                Ok(Signed::Fresh)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, Local};
    use vyrn_types::Mode;

    #[test]
    fn record_round_trips_and_rejects_bad_bytes() {
        let r = testkit::record();
        let b = encode_record(&r);
        assert_eq!(decode_record(&b), Ok(r));
        assert_eq!(decode_record(&b[..119]), Err(HandoffErr::Length));
        let mut bad = b;
        bad[3] = 1;
        assert_eq!(decode_record(&bad), Err(HandoffErr::Reserved));
        bad = b;
        bad[2] = 9;
        assert_eq!(decode_record(&bad), Err(HandoffErr::Home(9)));
    }

    #[test]
    fn certificate_sizes_match_08() {
        for (mode, len) in [(Mode::Base, 315), (Mode::Chain, 380)] {
            let (domain, old) = (testkit::domain(mode), testkit::old(mode));
            let cert = testkit::cert(
                &domain,
                &(0..u8::try_from(mode.quorum()).unwrap_or(0)).collect::<Vec<_>>(),
            );
            let bytes = cert.encode();
            assert_eq!(bytes.len(), len);
            assert_eq!(HandoffCert::decode(&bytes, mode.quorum()), Ok(cert.clone()));
            assert_eq!(verify_cert(&cert, &domain, &old), Ok(()));
        }
    }

    #[test]
    fn checks_run_in_order_and_map_to_actions() {
        let domain = testkit::domain(Mode::Base);
        let old = testkit::old(Mode::Base);
        let cert = testkit::cert(&domain, &[0, 1, 3]);
        let ok = Local::matching(&cert.record);
        assert_eq!(accept_cert(&cert, &domain, &old, &ok), Ok(()));

        // The same record under another genesis does not verify (§5.2).
        let other = Domain {
            genesis_hash: Hash([0xEE; 32]),
            ..domain
        };
        assert_eq!(
            accept_cert(&cert, &other, &old, &ok).map_err(HandoffErr::action),
            Err(Action::Alarm)
        );
        let cases: [(Local, HandoffErr); 5] = [
            (
                Local {
                    next_home: HomeCode::Nyc,
                    ..ok
                },
                HandoffErr::NotForMe,
            ),
            (Local { go: None, ..ok }, HandoffErr::SeqKey),
            (Local { head: None, ..ok }, HandoffErr::LogHash),
            (Local { root: None, ..ok }, HandoffErr::NoState),
            (
                Local {
                    root: Some(Hash([0; 32])),
                    ..ok
                },
                HandoffErr::StateRoot,
            ),
        ];
        for (local, err) in cases {
            assert_eq!(accept_cert(&cert, &domain, &old, &local), Err(err));
        }
        assert_eq!(HandoffErr::StateRoot.action(), Action::Resync);
        assert_eq!(HandoffErr::LogHash.action(), Action::FetchTail);
    }

    #[test]
    fn a_voter_signs_one_record_per_book_and_epoch() {
        let r = testkit::record();
        let mut once = SignOnce::default();
        assert_eq!(once.admit(&r), Ok(Signed::Fresh));
        assert_eq!(once.admit(&r), Ok(Signed::Repeat));
        let other = HandoffRecord {
            last_step: StepId(r.last_step.0 + 1),
            ..r
        };
        assert_eq!(once.admit(&other), Err(HandoffErr::Equivocation));
        // A restart keeps the rule.
        let mut again = SignOnce::from_persisted([(r.book, r.epoch, record_hash(&r))]);
        assert_eq!(again.admit(&other), Err(HandoffErr::Equivocation));
        // Another epoch is a fresh record.
        let next = HandoffRecord {
            epoch: Epoch(r.epoch.0 + 1),
            ..r
        };
        assert_eq!(once.admit(&next), Ok(Signed::Fresh));
    }

    #[test]
    fn the_builder_aggregates_on_receipt() {
        let domain = testkit::domain(Mode::Base);
        let old = testkit::old(Mode::Base);
        let r = testkit::record();
        let mut b = CertBuilder::new(r, &domain);
        for i in [3u8, 1] {
            let s = sign_record(&testkit::seed(i), i, &domain, &r);
            assert_eq!(b.add(&s, &old), Ok(()));
        }
        assert_eq!(b.cert(3), None);
        // A signature on another record is evidence, not a vote for this one.
        let other = HandoffRecord {
            last_step: StepId(1),
            ..r
        };
        let s = sign_record(&testkit::seed(0), 0, &domain, &other);
        assert_eq!(b.add(&s, &old), Err(HandoffErr::OtherRecord));
        // A forged signature from voter 2.
        let mut forged = sign_record(&testkit::seed(0), 2, &domain, &r);
        assert_eq!(b.add(&forged, &old), Err(HandoffErr::BadSig(2)));
        forged = sign_record(&testkit::seed(2), 2, &domain, &r);
        assert_eq!(b.add(&forged, &old), Ok(()));
        let cert = b.cert(3).unwrap_or_else(|| panic!("three signatures"));
        assert_eq!(cert.sigs.iter().map(|s| s.0).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(verify_cert(&cert, &domain, &old), Ok(()));
    }
}
