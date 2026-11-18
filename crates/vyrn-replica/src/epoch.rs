//! The replica's side of the epoch handoff (08 §5, §9): its [`EpochView`] over
//! `vyrn_epoch::Activation`, its `vyrn_epoch::LocalView`, the voter config of an epoch, and the
//! durable journal of `SignOnce` admissions and `armed(e+1)`.
//!
//! **Sequencer keys.** Frame headers name the sender by sequencer index, its position in
//! `REP_Membership.seq_order` (07 §2.2): 0 is the primary and 1 the standby. Spares (index ≥ 2)
//! have no key in `Activation`, so their frames never verify [Guessing: spec gap, PR body].
//!
//! **Fence.** `Activation.fence` is the fence of the epoch *before* this one. The fence of this
//! epoch exists only once its own `HandoffRecord` is certified; [`ActiveEpoch::set_fence`]
//! installs it, and from then on blocks above its `last_height` are fenced (07 §6.4 item 5).
//!
//! **Journal.** [`EpochJournal`] is an append-only text file, one fact per line:
//!
//! ```text
//! signed <book u16> <epoch u32> <record_hash 64 hex>
//! armed <epoch u32>
//! ```
//!
//! Each fact is written and fsynced before the call returns, so a caller signs or votes only
//! after its fact is durable (08 §5.3 rule 4, F4). On open, a last line without its `\n` is a
//! write that never completed and is dropped; any other malformed line fails the open. The file
//! holds an exclusive lock while open, so only one guard can admit records, and a newly created
//! journal's parent directory is fsynced before `open` returns.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use vyrn_consensus::voter::{Timeouts, VoterConfig};
use vyrn_epoch::{Activation, Fence, HandoffErr, LocalView, SignOnce, Signed, record_hash};
use vyrn_types::{BookId, Epoch, HandoffRecord, Hash, Height, HomeCode, PubKey, StepId};

use crate::ports::EpochView;

/// The epoch a replica serves, from its `Activation`.
#[derive(Clone, Debug)]
pub struct ActiveEpoch {
    pub activation: Activation,
    pub book: BookId,
    own_fence: Option<Fence>,
}

impl ActiveEpoch {
    pub const fn new(activation: Activation, book: BookId) -> Self {
        Self {
            activation,
            book,
            own_fence: None,
        }
    }

    /// Installs this epoch's own fence, from its certified `HandoffRecord`. A fence of another
    /// epoch is refused.
    pub fn set_fence(&mut self, fence: Fence) -> bool {
        let ok = fence.epoch() == self.activation.epoch;
        if ok {
            self.own_fence = Some(fence);
        }
        ok
    }

    /// The voter config of this epoch (07 §6.3) for the voter whose seed is `vote_seed`.
    pub fn voter_config<S>(
        &self,
        vote_seed: [u8; 32],
        source: S,
        timeouts: Timeouts,
    ) -> VoterConfig<S> {
        VoterConfig {
            committee: self.activation.committee.clone(),
            vote_seed,
            seq_key: self.activation.seq_key,
            epoch: self.activation.epoch,
            genesis: self.activation.genesis,
            source,
            timeouts,
        }
    }
}

impl EpochView for ActiveEpoch {
    fn epoch(&self) -> Epoch {
        self.activation.epoch
    }
    fn book(&self) -> BookId {
        self.book
    }
    fn seq_key(&self, sender: u8) -> Option<PubKey> {
        match sender {
            0 => Some(self.activation.seq_key),
            1 => Some(self.activation.standby_key),
            _ => None,
        }
    }
    fn fenced(&self, height: Height) -> bool {
        self.own_fence
            .is_some_and(|f| f.check_block(self.activation.epoch, height).is_err())
    }
}

/// What this replica holds from its own replay of epoch e, for 08 §5.4 checks 2–5. The order
/// core, the finality listener and replay fill it in as they learn each fact.
#[derive(Clone, Debug)]
pub struct ReplicaLocal {
    pub book: BookId,
    pub next_home: HomeCode,
    go: Option<(Epoch, PubKey)>,
    finals: BTreeMap<Height, Hash>,
    roots: BTreeMap<StepId, Hash>,
}

impl ReplicaLocal {
    pub const fn new(book: BookId, next_home: HomeCode) -> Self {
        Self {
            book,
            next_home,
            go: None,
            finals: BTreeMap::new(),
            roots: BTreeMap::new(),
        }
    }
    /// The final `EpoGo` this replica replayed in epoch e.
    pub fn set_go(&mut self, next_epoch: Epoch, next_seq_key: PubKey) {
        self.go = Some((next_epoch, next_seq_key));
    }
    /// A block this replica holds together with its finality certificate.
    pub fn record_final(&mut self, height: Height, header_hash: Hash) {
        self.finals.insert(height, header_hash);
    }
    /// This replica's state root after step `s`.
    pub fn record_root(&mut self, s: StepId, root: Hash) {
        self.roots.insert(s, root);
    }
}

impl LocalView for ReplicaLocal {
    fn book(&self) -> BookId {
        self.book
    }
    fn next_home(&self) -> HomeCode {
        self.next_home
    }
    fn go(&self) -> Option<(Epoch, PubKey)> {
        self.go
    }
    fn final_header_hash(&self, height: Height) -> Option<Hash> {
        self.finals.get(&height).copied()
    }
    fn state_root(&self, s: StepId) -> Option<Hash> {
        self.roots.get(&s).copied()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalErr {
    #[error("journal io: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal line {0} is malformed")]
    Line(usize),
    #[error(transparent)]
    Handoff(#[from] HandoffErr),
    #[error("an earlier write failed; reopen the journal")]
    Failed,
    #[error("the journal is open in another guard or process")]
    Locked,
}

/// The durable `SignOnce` admissions and `armed(e+1)` facts of one replica.
#[derive(Debug)]
pub struct EpochJournal {
    file: File,
    once: SignOnce,
    armed: BTreeSet<Epoch>,
    /// A write failed: memory may hold a fact the file lacks, so every later call fails until
    /// the journal is reopened.
    failed: bool,
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if s.len() != 64 {
        return None;
    }
    for (i, b) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2)?;
        *b = u8::from_str_radix(s.get(at..at.checked_add(2)?)?, 16).ok()?;
    }
    Some(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl EpochJournal {
    /// Opens or creates the journal at `path` and rebuilds its state.
    pub fn open(path: &Path) -> Result<Self, JournalErr> {
        let created = !path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        // One writer per journal: a second guard over the same file could admit a conflicting
        // record as Fresh. The lock is held for the life of `file`.
        file.try_lock().map_err(|_| JournalErr::Locked)?;
        if created {
            // A new file's directory entry is durable only once its parent directory is synced.
            let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
            File::open(dir.unwrap_or(Path::new(".")))?.sync_all()?;
        }
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let keep = text.rfind('\n').map_or(0, |i| i.saturating_add(1));
        let complete = text.get(..keep).unwrap_or("");
        let mut signed = Vec::new();
        let mut armed = BTreeSet::new();
        for (n, line) in complete.lines().enumerate() {
            let w: Vec<&str> = line.split(' ').collect();
            let bad = || JournalErr::Line(n.saturating_add(1));
            match w.as_slice() {
                ["signed", b, e, h] => signed.push((
                    BookId(b.parse().map_err(|_| bad())?),
                    Epoch(e.parse().map_err(|_| bad())?),
                    Hash(unhex32(h).ok_or_else(bad)?),
                )),
                ["armed", e] => {
                    armed.insert(Epoch(e.parse().map_err(|_| bad())?));
                }
                _ => return Err(bad()),
            }
        }
        if keep < text.len() {
            // Drop the torn tail so the next append starts on a fresh line.
            file.set_len(u64::try_from(keep).unwrap_or(0))?;
        }
        Ok(Self {
            file,
            once: SignOnce::from_persisted(signed),
            armed,
            failed: false,
        })
    }

    fn append(&mut self, line: &str) -> Result<(), JournalErr> {
        let r = self
            .file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_all());
        self.failed |= r.is_err();
        Ok(r?)
    }

    /// `SignOnce::admit`, with a `Fresh` admission made durable before it returns: the caller
    /// may sign and send once this is `Ok`.
    pub fn admit(&mut self, r: &HandoffRecord) -> Result<Signed, JournalErr> {
        if self.failed {
            return Err(JournalErr::Failed);
        }
        let s = self.once.admit(r)?;
        if s == Signed::Fresh {
            let line = format!(
                "signed {} {} {}\n",
                r.book.0,
                r.epoch.0,
                hex(&record_hash(r).0)
            );
            self.append(&line)?;
        }
        Ok(s)
    }

    /// Persists `armed(epoch)`: this node verified cert(e, S) and may vote in `epoch` (F4).
    pub fn arm(&mut self, epoch: Epoch) -> Result<(), JournalErr> {
        if self.failed {
            return Err(JournalErr::Failed);
        }
        if self.armed.contains(&epoch) {
            return Ok(());
        }
        self.append(&format!("armed {}\n", epoch.0))?;
        self.armed.insert(epoch);
        Ok(())
    }

    pub fn is_armed(&self, epoch: Epoch) -> bool {
        self.armed.contains(&epoch)
    }
}
