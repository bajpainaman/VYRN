//! The drop-copy service (10 §8.5): a store of every stream's records for the replay window,
//! and the per-connection session that authenticates, checks the subscription rule and
//! streams from any point. Transport-agnostic: the binary moves its frames over TCP.
//!
//! # Session
//!
//! 1. The server sends `HELLO` with a fresh 32-byte challenge.
//! 2. The client sends one 128-byte login. The server checks, in this order: the form
//!    (`Malformed`), the book (`Book`), the signer's key and the signature over this
//!    connection's challenge (`Auth`), the subscription rule (`Denied`), the stream (`Stream`),
//!    the epoch (`Epoch`) and `from` (`Range`). The first failure is a `REJECT` and the
//!    connection ends.
//! 3. Otherwise `ACCEPT(from, newest)`, then every record from `from` on, in seq order, gapless.
//!    A previous epoch's stream ends with `END(last seq)`, and the current epoch's continues
//!    at seq 1. Idle streams send `HEARTBEAT(last seq sent)`.
//!
//! **Subscription rule.** An account reads its own stream; a master reads its own master
//! stream and each sub-account's own stream. Nobody else reads a stream.
//!
//! **Gap recovery.** Seqs are gapless per stream and epoch, and `HEARTBEAT` names the last
//! seq sent, so a client sees a gap at the next frame. It reconnects with `from` = its last
//! seq + 1; the store holds the current and the previous epoch (`MD_DC_REPLAY_EPOCHS`).

use std::collections::{BTreeMap, VecDeque};

use vyrn_types::{AccountId, BookId, Epoch};

use super::record::DcRecord;
use super::wire::{Frame, FrameKind, LOGIN_BYTES, Login, RejectReason};
use super::{DcOut, MD_DC_REPLAY_EPOCHS, StreamId};

/// The records of one epoch, per stream, and whether the epoch has ended.
#[derive(Clone, Debug, Default)]
struct EpochRecs {
    epoch: Epoch,
    streams: BTreeMap<StreamId, Vec<DcRecord>>,
    ended: bool,
}

/// Every stream's records for the replay window. A [`DcOut`] for the current epoch.
#[derive(Clone, Debug, Default)]
pub struct DcStore {
    epochs: VecDeque<EpochRecs>,
}

impl DcStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts `epoch` (ending the one before) and drops epochs outside the window.
    pub fn begin_epoch(&mut self, epoch: Epoch) {
        if let Some(e) = self.epochs.back_mut() {
            e.ended = true;
        }
        self.epochs.push_back(EpochRecs {
            epoch,
            ..EpochRecs::default()
        });
        while self.epochs.len() > MD_DC_REPLAY_EPOCHS {
            self.epochs.pop_front();
        }
    }

    /// Marks the current epoch ended (its `DC_EOD`s are in).
    pub fn end_epoch(&mut self) {
        if let Some(e) = self.epochs.back_mut() {
            e.ended = true;
        }
    }

    /// Makes `stream` known in the current epoch even before its first record.
    pub fn open(&mut self, stream: StreamId) {
        if let Some(e) = self.epochs.back_mut() {
            e.streams.entry(stream).or_default();
        }
    }

    pub fn current(&self) -> Option<Epoch> {
        self.epochs.back().map(|e| e.epoch)
    }

    fn get(&self, epoch: Epoch) -> Option<&EpochRecs> {
        self.epochs.iter().find(|e| e.epoch == epoch)
    }

    /// The epoch after `epoch` in the window.
    fn next(&self, epoch: Epoch) -> Option<Epoch> {
        let i = self.epochs.iter().position(|e| e.epoch == epoch)?;
        self.epochs.get(i + 1).map(|e| e.epoch)
    }

    /// Records of `stream` in `epoch` (seq `i + 1` at index `i`).
    pub fn records(&self, epoch: Epoch, stream: StreamId) -> &[DcRecord] {
        self.get(epoch)
            .and_then(|e| e.streams.get(&stream))
            .map_or(&[], Vec::as_slice)
    }
}

impl DcOut for DcStore {
    fn push(&mut self, stream: StreamId, seq: u64, rec: &DcRecord) {
        if let Some(e) = self.epochs.back_mut() {
            let v = e.streams.entry(stream).or_default();
            debug_assert_eq!(v.len() as u64 + 1, seq);
            v.push(*rec);
        }
    }
}

/// Who may log in: each account's Ed25519 key and master.
#[derive(Clone, Debug, Default)]
pub struct Keys {
    keys: BTreeMap<AccountId, [u8; 32]>,
    master: BTreeMap<AccountId, AccountId>,
}

impl Keys {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, account: AccountId, key: [u8; 32], master: Option<AccountId>) {
        self.keys.insert(account, key);
        if let Some(m) = master.filter(|m| *m != account) {
            self.master.insert(account, m);
        }
    }

    /// The subscription rule (module docs).
    pub fn may_read(&self, signer: AccountId, stream: StreamId) -> bool {
        if stream.master {
            signer == stream.account
        } else {
            signer == stream.account || self.master.get(&stream.account) == Some(&signer)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Hello,
    Streaming {
        stream: StreamId,
        epoch: Epoch,
        next: u64,
    },
    Closed,
}

/// One client connection (module docs).
#[derive(Clone, Debug)]
pub struct Session {
    book: BookId,
    challenge: [u8; 32],
    state: State,
    /// The last seq sent and whether anything was sent since the last heartbeat check.
    last: u64,
    busy: bool,
}

impl Session {
    /// A session whose `HELLO` carries `challenge` (fresh per connection).
    pub fn new(book: BookId, challenge: [u8; 32]) -> Self {
        Self {
            book,
            challenge,
            state: State::Hello,
            last: 0,
            busy: false,
        }
    }

    pub fn hello(&self, store: &DcStore) -> Frame {
        Frame::hello(
            self.book,
            store.current().unwrap_or(Epoch(0)),
            &self.challenge,
        )
    }

    pub fn closed(&self) -> bool {
        self.state == State::Closed
    }

    /// The client's login. `ACCEPT` streams from then on; `REJECT` closes the session.
    pub fn login(&mut self, b: &[u8; LOGIN_BYTES], keys: &Keys, store: &DcStore) -> Frame {
        match self.check(b, keys, store) {
            Ok((stream, epoch, from)) => {
                self.state = State::Streaming {
                    stream,
                    epoch,
                    next: from,
                };
                self.last = from - 1;
                let newest = store.records(epoch, stream).len() as u64;
                Frame::accept(self.book, epoch, from, newest)
            }
            Err(why) => {
                self.state = State::Closed;
                Frame::reject(self.book, store.current().unwrap_or(Epoch(0)), why)
            }
        }
    }

    fn check(
        &self,
        b: &[u8; LOGIN_BYTES],
        keys: &Keys,
        store: &DcStore,
    ) -> Result<(StreamId, Epoch, u64), RejectReason> {
        if self.state != State::Hello {
            return Err(RejectReason::Malformed);
        }
        let (l, sig) = Login::decode(b).ok_or(RejectReason::Malformed)?;
        if l.book != self.book {
            return Err(RejectReason::Book);
        }
        let key = keys.keys.get(&l.signer).ok_or(RejectReason::Auth)?;
        if l.challenge != self.challenge
            || !vyrn_crypto::ed25519::verify(key, &l.signed_message(), &sig)
        {
            return Err(RejectReason::Auth);
        }
        let stream = StreamId {
            account: l.account,
            master: l.master,
        };
        if !keys.may_read(l.signer, stream) {
            return Err(RejectReason::Denied);
        }
        let e = store.get(l.epoch).ok_or(RejectReason::Epoch)?;
        let recs = e.streams.get(&stream).ok_or(RejectReason::Stream)?;
        if l.from == 0 || l.from > recs.len() as u64 + 1 {
            return Err(RejectReason::Range);
        }
        Ok((stream, l.epoch, l.from))
    }

    /// Every frame due now: the records from the session's next seq on, and `END` and the next
    /// epoch's records when a previous epoch's stream is used up. At most `max` frames. A
    /// session whose epoch left the replay window gets `REJECT(Epoch)` and is closed.
    pub fn poll(&mut self, store: &DcStore, max: usize) -> Vec<Frame> {
        let mut out = Vec::new();
        while out.len() < max {
            let State::Streaming {
                stream,
                epoch,
                next,
            } = self.state
            else {
                break;
            };
            if store.get(epoch).is_none() {
                // The session fell behind the replay window: it cannot resume here.
                out.push(Frame::reject(self.book, epoch, RejectReason::Epoch));
                self.state = State::Closed;
                break;
            }
            let recs = store.records(epoch, stream);
            if let Some(r) = usize::try_from(next - 1).ok().and_then(|i| recs.get(i)) {
                out.push(Frame::record(self.book, epoch, next, r));
                self.last = next;
                self.busy = true;
                self.state = State::Streaming {
                    stream,
                    epoch,
                    next: next + 1,
                };
                continue;
            }
            // Used up. A previous, ended epoch hands over to the next one at seq 1.
            let ended = store.get(epoch).is_some_and(|e| e.ended);
            match store.next(epoch).filter(|_| ended) {
                Some(n) => {
                    out.push(Frame::bare(FrameKind::End, self.book, epoch, next - 1));
                    self.state = State::Streaming {
                        stream,
                        epoch: n,
                        next: 1,
                    };
                    self.last = 0;
                    self.busy = true;
                }
                None => break,
            }
        }
        out
    }

    /// Called every `DC_HEARTBEAT_MS`: a `HEARTBEAT(last seq sent)` when nothing went out
    /// since the last call.
    pub fn tick(&mut self) -> Option<Frame> {
        let State::Streaming { epoch, .. } = self.state else {
            return None;
        };
        let idle = !self.busy;
        self.busy = false;
        idle.then(|| Frame::bare(FrameKind::Heartbeat, self.book, epoch, self.last))
    }
}

impl DcStore {
    /// A store from `store <epoch> <account> <master 0|1> <seq> <hex>` lines (other lines are
    /// skipped), in epoch order: the input of `vyrn-dropcopy --records` until the observer's
    /// output ring feeds a [`DropCopy`](super::DropCopy) directly.
    pub fn load_text(text: &str) -> Result<Self, String> {
        let mut s = Self::new();
        for (n, line) in text.lines().enumerate() {
            let w: Vec<&str> = line.split_whitespace().collect();
            if w.first() != Some(&"store") {
                continue;
            }
            let bad = || format!("line {}: {line}", n + 1);
            let [_, e, a, m, q, h] = w.as_slice() else {
                return Err(bad());
            };
            let e = Epoch(e.parse().map_err(|_| bad())?);
            if s.current() != Some(e) {
                if s.epochs.iter().any(|x| x.epoch == e) {
                    return Err(bad());
                }
                s.begin_epoch(e);
            }
            let id = StreamId {
                account: AccountId(a.parse().map_err(|_| bad())?),
                master: *m == "1",
            };
            let q: u64 = q.parse().map_err(|_| bad())?;
            let bytes = (0..h.len())
                .step_by(2)
                .map(|i| h.get(i..i + 2).and_then(|x| u8::from_str_radix(x, 16).ok()))
                .collect::<Option<Vec<u8>>>()
                .ok_or_else(bad)?;
            let b: [u8; super::DC_REC_BYTES] = bytes.try_into().map_err(|_| bad())?;
            let r = DcRecord::decode(&b).map_err(|_| bad())?;
            if q != s.records(e, id).len() as u64 + 1 {
                return Err(bad());
            }
            s.push(id, q, &r);
        }
        Ok(s)
    }
}

/// The store, read-locked; a poisoned lock ends the connection.
fn read(
    s: &std::sync::RwLock<DcStore>,
) -> std::io::Result<std::sync::RwLockReadGuard<'_, DcStore>> {
    s.read()
        .map_err(|_| std::io::Error::other("store lock poisoned"))
}

/// Wakes serving connections when the store grows. The writer calls [`Wake::bump`] after it
/// pushes records (and after `end_epoch`), so a session sends them at once instead of at its
/// next heartbeat.
#[derive(Debug, Default)]
pub struct Wake {
    count: std::sync::Mutex<u64>,
    cv: std::sync::Condvar,
}

impl Wake {
    pub fn new() -> Self {
        Self::default()
    }

    /// The store changed.
    pub fn bump(&self) {
        if let Ok(mut g) = self.count.lock() {
            *g = g.wrapping_add(1);
        }
        self.cv.notify_all();
    }

    /// The current generation.
    pub fn generation(&self) -> u64 {
        self.count.lock().map_or(0, |g| *g)
    }

    /// Waits up to `d` for a generation other than `seen`.
    pub fn wait(&self, seen: u64, d: std::time::Duration) {
        if let Ok(g) = self.count.lock() {
            let _ = self.cv.wait_timeout_while(g, d, |g| *g == seen);
        }
    }
}

/// Serves one connection to its end (module docs): `HELLO`, the login, then records as the
/// store grows ([`Wake`]) and a heartbeat every `DC_HEARTBEAT_MS` without one. `timeout` sets
/// the transport's read and write timeouts: the time left of `login_timeout` before `HELLO`
/// and each login read, so a client that sends its login slowly or not at all is dropped when
/// it runs out, then `DC_WRITE_TIMEOUT_MS`, so a subscriber that stops draining its stream is
/// dropped. Returns when the session closes or I/O fails (a client that closes fails the next
/// write, at the latest its next heartbeat).
pub fn serve<S: std::io::Read + std::io::Write>(
    io: &mut S,
    mut sess: Session,
    keys: &Keys,
    store: &std::sync::RwLock<DcStore>,
    wake: &Wake,
    login_timeout: std::time::Duration,
    mut timeout: impl FnMut(&mut S, std::time::Duration) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::io::ErrorKind;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + login_timeout;
    timeout(io, login_timeout)?;
    let hello = sess.hello(&*read(store)?);
    io.write_all(&hello.encode())?;
    let mut login = [0; LOGIN_BYTES];
    let mut got = 0;
    while got < LOGIN_BYTES {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ErrorKind::TimedOut.into());
        }
        timeout(io, left)?;
        match io.read(&mut login[got..]) {
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let first = sess.login(&login, keys, &*read(store)?);
    io.write_all(&first.encode())?;
    if sess.closed() {
        return Ok(());
    }
    timeout(io, Duration::from_millis(super::wire::DC_WRITE_TIMEOUT_MS))?;
    let hb = Duration::from_millis(super::wire::DC_HEARTBEAT_MS);
    let mut next_hb = Instant::now() + hb;
    loop {
        // Read the generation first: a record pushed after this poll ends the wait below.
        let seen = wake.generation();
        let frames = sess.poll(&*read(store)?, 256);
        for f in &frames {
            io.write_all(&f.encode())?;
        }
        if !frames.is_empty() || sess.closed() {
            io.flush()?;
        }
        if sess.closed() {
            return Ok(());
        }
        if !frames.is_empty() {
            continue;
        }
        let now = Instant::now();
        if now >= next_hb {
            if let Some(f) = sess.tick() {
                io.write_all(&f.encode())?;
                io.flush()?;
            }
            next_hb = now + hb;
            continue;
        }
        wake.wait(seen, next_hb - now);
    }
}
