//! The observer's output ring to `vyrn-dropcopy` (03 §4.5, 10 §8.6).
//!
//! 03 §4.5 has `vyrn-dropcopy` run as a separate process that maps the replica's output rings
//! read-only, so a crash in it never stops replay. 11 §3.2 closes the `unsafe` list, so there is
//! no `mmap` here: the ring is a file under `/dev/shm` (tmpfs, so the page cache is the shared
//! memory) that [`RingTap`] writes with `pwrite` and [`RingReader`] reads with `pread`
//! (\[Guessing\], 10 §8.6 item 1).
//!
//! [`RingTap`] is the [`Tap`] of the observer's `SinkStream`, the same sink that feeds `vyrn-md`,
//! so the drop copy sees exactly the replay events the market data sees. The observer's shell
//! adds the inputs no replay output carries ([`RingTap::final_block`], [`RingTap::alloc`], …).
//! `vyrn-dropcopy` applies each [`RingFrame`] to its [`DropCopy`] ([`RingFrame::apply`]), so its
//! records are the records an in-process `DropCopy` tap would make, byte for byte.
//!
//! Layout (all little-endian):
//!
//! | Offset | Bytes | Field |
//! |---|---|---|
//! | 0 | 8 | magic `VYRNDCR1` |
//! | 8 | 8 | `cap`, the data region's size |
//! | 16 | 8 | `head`: bytes ever written |
//! | 24 | 8 | `!head` |
//! | 32 | 8 | `resv`: bytes written once the batch in flight lands |
//! | 40 | 8 | `!resv` |
//! | 64 | `cap` | data, byte `i` of the stream at `64 + i % cap` |
//!
//! The writer first publishes `resv` and `!resv` in one `pwrite`, then writes a batch of whole
//! frames, then `head` and `!head` in one `pwrite`. A reader that sees a pair disagree read a
//! torn header and reads it again. A reader whose `tail` is more than `cap` behind `head` before
//! it copies the bytes, or behind `resv` after, has lost data and stops with
//! [`RingError::Lagged`]: the writer never waits for a reader (03 §4.5), and a lagged drop
//! copy is rebuilt from the final log (03 §7).
//!
//! A frame is `len: u32` then `len` bytes: a kind byte and its fields ([`RingFrame`], 10 §8.6
//! item 2).

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::{Arc, RwLock};

use vyrn_replica::sink::{Record as Resp, TxEntry};
use vyrn_types::{AccountId, BookId, Epoch, Height, LaneId, LaneSeq, SessionId, StepId, StepKind};
use vyrn_wire::Msg;

use super::server::{DcStore, Wake};
use super::{Alloc, AllocAsset, Balances, DcError, DcOut, DcRecord, DcRoute, DropCopy, StreamId};
use crate::replay::{Tap, TapOp, TapSrc, TapStep};

pub const RING_MAGIC: [u8; 8] = *b"VYRNDCR1";
/// Bytes before the data region.
pub const RING_HEADER: u64 = 64;
/// Default data region: 64 MiB (\[Guessing\], 10 §8.6 item 3).
pub const RING_CAP: u64 = 64 << 20;
/// Header reads before a reader gives up on a torn header.
const TORN_RETRIES: u32 = 1_000;

const K_OP: u8 = 1;
const K_STEP: u8 = 2;
const K_FINAL: u8 = 3;
const K_ALLOC: u8 = 4;
const K_SETTLED: u8 = 5;
const K_REVERT: u8 = 6;
const K_ROUTE: u8 = 7;
const K_BEGIN: u8 = 8;
const K_END: u8 = 9;

/// Why the ring stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RingError {
    Io(String),
    Magic,
    Torn,
    /// The writer overwrote bytes from `tail` on before the reader took them.
    Lagged {
        tail: u64,
        head: u64,
    },
    /// A frame that does not decode, at stream offset `at`.
    Frame {
        at: u64,
    },
    /// A batch larger than the ring.
    TooBig(usize),
}

impl std::fmt::Display for RingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "drop-copy ring: {self:?}")
    }
}

impl std::error::Error for RingError {}

fn io(e: std::io::Error) -> RingError {
    RingError::Io(e.to_string())
}

/// One ring frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RingFrame {
    /// [`Tap::lane_op`].
    Op(TapOp),
    /// [`Tap::step`].
    Step {
        step: StepId,
        kind: StepKind,
        flags: u8,
        src: Option<TapSrc>,
        tx: Vec<(TxEntry, Resp)>,
    },
    /// [`DropCopy::final_block`].
    Final(Height, StepId),
    /// [`DropCopy::alloc`].
    Alloc(Alloc),
    /// [`DropCopy::settled`].
    Settled(Height, StepId),
    /// [`DropCopy::revert_after`].
    Revert(StepId),
    /// [`DropCopy::route`].
    Route(DcRoute),
    /// A new epoch: the reader starts a new [`DropCopy`].
    Begin(Epoch),
    /// [`DropCopy::end_epoch`] with each account's closing balances.
    End(Vec<(AccountId, Balances)>),
}

impl RingFrame {
    /// Applies the frame to `dc`. [`RingFrame::Begin`] is the caller's: it changes nothing here.
    pub fn apply<O: DcOut>(&self, dc: &mut DropCopy<O>) -> Result<(), DcError> {
        match self {
            Self::Op(op) => dc.lane_op(op),
            Self::Step {
                step,
                kind,
                flags,
                src,
                tx,
            } => dc.step(&TapStep {
                step: *step,
                kind: *kind,
                flags: *flags,
                src: *src,
                tx,
            }),
            Self::Final(h, s) => dc.final_block(*h, *s),
            Self::Alloc(a) => dc.alloc(*a),
            Self::Settled(h, s) => dc.settled(*h, *s),
            Self::Revert(k) => dc.revert_after(*k),
            Self::Route(r) => dc.route(r),
            Self::Begin(_) => {}
            Self::End(b) => {
                return dc.end_epoch(|a| {
                    b.iter()
                        .find(|(x, _)| *x == a)
                        .map_or_else(Balances::default, |(_, b)| *b)
                });
            }
        }
        dc.error().map_or(Ok(()), Err)
    }

    /// Appends the frame, with its length prefix, to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let at = out.len();
        out.extend_from_slice(&[0; 4]);
        match self {
            Self::Op(op) => {
                out.push(K_OP);
                out.push(op.lane.0);
                out.extend_from_slice(&op.seq.0.to_le_bytes());
                out.extend_from_slice(&op.session.0.to_le_bytes());
                out.extend_from_slice(&op.pkt_seq.to_le_bytes());
                out.extend_from_slice(&op.resp_seq.to_le_bytes());
                put_msg(out, op.msg);
                out.extend_from_slice(&op.rec.encode());
            }
            Self::Step {
                step,
                kind,
                flags,
                src,
                tx,
            } => {
                out.push(K_STEP);
                out.extend_from_slice(&step.0.to_le_bytes());
                out.push(kind.code());
                out.push(*flags);
                match src {
                    None => out.extend_from_slice(&[0; 31]),
                    Some(s) => {
                        out.push(1);
                        out.push(s.lane.0);
                        out.extend_from_slice(&s.seq.0.to_le_bytes());
                        out.extend_from_slice(&s.session.0.to_le_bytes());
                        put_msg(out, s.msg);
                    }
                }
                let n = u16::try_from(tx.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&n.to_le_bytes());
                for (h, r) in tx.iter().take(usize::from(n)) {
                    out.extend_from_slice(&h.step.0.to_le_bytes());
                    out.extend_from_slice(&h.session.0.to_le_bytes());
                    out.extend_from_slice(&h.resp_seq.to_le_bytes());
                    out.extend_from_slice(&h.pkt_seq.to_le_bytes());
                    out.extend_from_slice(&[h.lane.0, h.n_rec, h.role]);
                    out.extend_from_slice(&r.encode());
                }
            }
            Self::Final(h, s) | Self::Settled(h, s) => {
                out.push(if matches!(self, Self::Final(..)) {
                    K_FINAL
                } else {
                    K_SETTLED
                });
                out.extend_from_slice(&h.0.to_le_bytes());
                out.extend_from_slice(&s.0.to_le_bytes());
            }
            Self::Alloc(a) => {
                out.push(K_ALLOC);
                out.extend_from_slice(&a.step.0.to_le_bytes());
                out.extend_from_slice(&a.account.0.to_le_bytes());
                out.push(a.asset as u8);
                out.push(u8::from(a.debit));
                out.extend_from_slice(&a.amount.to_le_bytes());
            }
            Self::Revert(k) => {
                out.push(K_REVERT);
                out.extend_from_slice(&k.0.to_le_bytes());
            }
            Self::Route(r) => {
                out.push(K_ROUTE);
                out.extend_from_slice(&r.account.0.to_le_bytes());
                out.extend_from_slice(&r.session.0.to_le_bytes());
                out.extend_from_slice(&r.lane_seq.to_le_bytes());
                out.push(r.index);
                out.extend_from_slice(&r.resp_seq.to_le_bytes());
                out.push(r.asset);
                out.extend_from_slice(&r.to_book.0.to_le_bytes());
                out.extend_from_slice(&r.amount.to_le_bytes());
                out.extend_from_slice(&r.client_tag.to_le_bytes());
                out.extend_from_slice(&r.fee.to_le_bytes());
            }
            Self::Begin(e) => {
                out.push(K_BEGIN);
                out.extend_from_slice(&e.0.to_le_bytes());
            }
            Self::End(b) => {
                out.push(K_END);
                let n = u32::try_from(b.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&n.to_le_bytes());
                for (a, x) in b.iter().take(n as usize) {
                    out.extend_from_slice(&a.0.to_le_bytes());
                    for w in [x.quote_free, x.quote_resv, x.base_free, x.base_resv] {
                        out.extend_from_slice(&w.to_le_bytes());
                    }
                }
            }
        }
        let len = u32::try_from(out.len() - at - 4).unwrap_or(u32::MAX);
        if let Some(p) = out.get_mut(at..at + 4) {
            p.copy_from_slice(&len.to_le_bytes());
        }
    }

    /// One frame body (after its length prefix).
    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut c = Cur(b);
        let f = match c.u8()? {
            K_OP => Self::Op(TapOp {
                lane: LaneId(c.u8()?),
                seq: LaneSeq(c.u64()?),
                session: SessionId(c.u32()?),
                pkt_seq: c.u32()?,
                resp_seq: c.u32()?,
                msg: c.msg()?,
                rec: c.rec()?,
            }),
            K_STEP => {
                let step = StepId(c.u64()?);
                let kind = StepKind::from_code(c.u8()?)?;
                let flags = c.u8()?;
                let src = match c.u8()? {
                    0 => {
                        c.take(30)?;
                        None
                    }
                    1 => Some(TapSrc {
                        lane: LaneId(c.u8()?),
                        seq: LaneSeq(c.u64()?),
                        session: SessionId(c.u32()?),
                        msg: c.msg()?,
                    }),
                    _ => return None,
                };
                let n = c.u16()?;
                let mut tx = Vec::with_capacity(usize::from(n));
                for _ in 0..n {
                    let h = TxEntry {
                        step: StepId(c.u64()?),
                        session: SessionId(c.u32()?),
                        resp_seq: c.u32()?,
                        pkt_seq: c.u32()?,
                        lane: LaneId(c.u8()?),
                        n_rec: c.u8()?,
                        role: c.u8()?,
                    };
                    tx.push((h, c.rec()?));
                }
                Self::Step {
                    step,
                    kind,
                    flags,
                    src,
                    tx,
                }
            }
            K_FINAL => Self::Final(Height(c.u64()?), StepId(c.u64()?)),
            K_SETTLED => Self::Settled(Height(c.u64()?), StepId(c.u64()?)),
            K_ALLOC => Self::Alloc(Alloc {
                step: StepId(c.u64()?),
                account: AccountId(c.u32()?),
                asset: match c.u8()? {
                    0 => AllocAsset::Quote,
                    1 => AllocAsset::Base,
                    _ => return None,
                },
                debit: match c.u8()? {
                    0 => false,
                    1 => true,
                    _ => return None,
                },
                amount: c.u64()?,
            }),
            K_REVERT => Self::Revert(StepId(c.u64()?)),
            K_ROUTE => Self::Route(DcRoute {
                account: AccountId(c.u32()?),
                session: SessionId(c.u32()?),
                lane_seq: c.u64()?,
                index: c.u8()?,
                resp_seq: c.u32()?,
                asset: c.u8()?,
                to_book: BookId(c.u16()?),
                amount: c.u64()?,
                client_tag: c.u32()?,
                fee: i64::from_le_bytes(c.arr()?),
            }),
            K_BEGIN => Self::Begin(Epoch(c.u32()?)),
            K_END => {
                let n = c.u32()?;
                let mut v = Vec::new();
                for _ in 0..n {
                    let a = AccountId(c.u32()?);
                    v.push((
                        a,
                        Balances {
                            quote_free: c.u64()?,
                            quote_resv: c.u64()?,
                            base_free: c.u64()?,
                            base_resv: c.u64()?,
                        },
                    ));
                }
                Self::End(v)
            }
            _ => return None,
        };
        c.0.is_empty().then_some(f)
    }
}

/// `has: u8` then the 16 message bytes (zero when absent).
fn put_msg(out: &mut Vec<u8>, m: Option<Msg>) {
    match m {
        None => out.extend_from_slice(&[0; 17]),
        Some(m) => {
            out.push(1);
            out.extend_from_slice(&m.encode());
        }
    }
}

struct Cur<'a>(&'a [u8]);

impl Cur<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn arr<const K: usize>(&mut self) -> Option<[u8; K]> {
        self.take(K)?.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.arr::<1>()?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.arr()?))
    }
    fn msg(&mut self) -> Option<Option<Msg>> {
        let has = self.u8()?;
        let b: [u8; 16] = self.arr()?;
        match has {
            0 => Some(None),
            1 => Msg::decode(&b).ok().map(Some),
            _ => None,
        }
    }
    fn rec(&mut self) -> Option<Resp> {
        Resp::decode(&self.arr()?)
    }
}

/// The writing end: the observer's `SinkStream` tap, and the shell's inputs (module docs).
///
/// Lane ops wait in a buffer; a step, a shell input or a full buffer publishes the buffer
/// (one data `pwrite`, one header `pwrite`). The first error stops it ([`RingTap::error`]).
pub struct RingTap {
    file: File,
    cap: u64,
    head: u64,
    buf: Vec<u8>,
    err: Option<RingError>,
}

impl RingTap {
    /// Creates (or truncates) the ring at `path` with a data region of `cap` bytes.
    pub fn create(path: &Path, cap: u64) -> Result<Self, RingError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(io)?;
        file.set_len(RING_HEADER + cap).map_err(io)?;
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&RING_MAGIC);
        h[8..16].copy_from_slice(&cap.to_le_bytes());
        h[24..32].copy_from_slice(&(!0u64).to_le_bytes());
        file.write_all_at(&h, 0).map_err(io)?;
        file.write_all_at(&pair(0), 32).map_err(io)?;
        Ok(Self {
            file,
            cap,
            head: 0,
            buf: Vec::new(),
            err: None,
        })
    }

    pub fn error(&self) -> Option<&RingError> {
        self.err.as_ref()
    }

    /// Bytes published so far.
    pub fn head(&self) -> u64 {
        self.head
    }

    pub fn begin_epoch(&mut self, e: Epoch) {
        self.send(&RingFrame::Begin(e));
    }
    pub fn end_epoch(&mut self, balances: Vec<(AccountId, Balances)>) {
        self.send(&RingFrame::End(balances));
    }
    pub fn final_block(&mut self, h: Height, last_step: StepId) {
        self.send(&RingFrame::Final(h, last_step));
    }
    pub fn alloc(&mut self, a: Alloc) {
        self.send(&RingFrame::Alloc(a));
    }
    pub fn settled(&mut self, h: Height, last_step: StepId) {
        self.send(&RingFrame::Settled(h, last_step));
    }
    pub fn revert_after(&mut self, kept: StepId) {
        self.send(&RingFrame::Revert(kept));
    }
    pub fn route(&mut self, r: &DcRoute) {
        self.send(&RingFrame::Route(*r));
    }

    fn send(&mut self, f: &RingFrame) {
        f.encode(&mut self.buf);
        self.flush();
    }

    /// Publishes the buffered frames.
    pub fn flush(&mut self) {
        if self.err.is_some() || self.buf.is_empty() {
            self.buf.clear();
            return;
        }
        if let Err(e) = self.publish() {
            self.err = Some(e);
        }
        self.buf.clear();
    }

    fn publish(&mut self) -> Result<(), RingError> {
        let n = self.buf.len() as u64;
        if n > self.cap {
            return Err(RingError::TooBig(self.buf.len()));
        }
        // Readers see the batch's end before any byte it overwrites (module docs).
        self.file
            .write_all_at(&pair(self.head + n), 32)
            .map_err(io)?;
        let at = self.head % self.cap;
        let first = usize::try_from((self.cap - at).min(n)).map_err(|_| RingError::TooBig(0))?;
        let (a, b) = self.buf.split_at(first);
        self.file.write_all_at(a, RING_HEADER + at).map_err(io)?;
        if !b.is_empty() {
            self.file.write_all_at(b, RING_HEADER).map_err(io)?;
        }
        self.head += n;
        self.file.write_all_at(&pair(self.head), 16).map_err(io)
    }
}

impl Tap for RingTap {
    fn lane_op(&mut self, op: &TapOp) {
        RingFrame::Op(*op).encode(&mut self.buf);
        if self.buf.len() as u64 > self.cap / 4 {
            self.flush();
        }
    }

    fn step(&mut self, st: &TapStep<'_>) {
        let f = RingFrame::Step {
            step: st.step,
            kind: st.kind,
            flags: st.flags,
            src: st.src,
            tx: st.tx.to_vec(),
        };
        self.send(&f);
    }
}

/// `x` then `!x`, the torn-read check of a header word.
fn pair(x: u64) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[..8].copy_from_slice(&x.to_le_bytes());
    h[8..].copy_from_slice(&(!x).to_le_bytes());
    h
}

/// The reading end, in `vyrn-dropcopy`. It starts at offset 0: a ring that has wrapped before
/// the reader opens it is [`RingError::Lagged`].
pub struct RingReader {
    file: File,
    cap: u64,
    tail: u64,
    buf: Vec<u8>,
}

impl RingReader {
    pub fn open(path: &Path) -> Result<Self, RingError> {
        let file = File::open(path).map_err(io)?;
        let mut h = [0u8; 16];
        file.read_exact_at(&mut h, 0).map_err(io)?;
        if h[..8] != RING_MAGIC {
            return Err(RingError::Magic);
        }
        let cap = u64::from_le_bytes(h[8..16].try_into().map_err(|_| RingError::Magic)?);
        if cap == 0 {
            return Err(RingError::Magic);
        }
        Ok(Self {
            file,
            cap,
            tail: 0,
            buf: Vec::new(),
        })
    }

    /// Bytes taken so far.
    pub fn tail(&self) -> u64 {
        self.tail
    }

    /// `head`, read again until `head` and `!head` agree.
    fn head(&self) -> Result<u64, RingError> {
        self.word(16)
    }

    /// The header word pair at `off`, read again until the pair agrees.
    fn word(&self, off: u64) -> Result<u64, RingError> {
        let mut h = [0u8; 16];
        for _ in 0..TORN_RETRIES {
            self.file.read_exact_at(&mut h, off).map_err(io)?;
            let a = u64::from_le_bytes(h[..8].try_into().map_err(|_| RingError::Torn)?);
            let b = u64::from_le_bytes(h[8..].try_into().map_err(|_| RingError::Torn)?);
            if a == !b {
                return Ok(a);
            }
        }
        Err(RingError::Torn)
    }

    fn lagged(&self, head: u64) -> Result<(), RingError> {
        if head < self.tail || head - self.tail > self.cap {
            return Err(RingError::Lagged {
                tail: self.tail,
                head,
            });
        }
        Ok(())
    }

    /// Takes every frame published since the last call, in order, and hands each to `f`.
    /// Returns the number of frames.
    pub fn poll(&mut self, mut f: impl FnMut(RingFrame)) -> Result<usize, RingError> {
        let head = self.head()?;
        self.lagged(head)?;
        if head == self.tail {
            return Ok(0);
        }
        let n = usize::try_from(head - self.tail).map_err(|_| RingError::TooBig(0))?;
        self.buf.resize(n, 0);
        let at = self.tail % self.cap;
        let first = usize::try_from((self.cap - at).min(n as u64)).unwrap_or(n);
        let (a, b) = self.buf.split_at_mut(first);
        self.file.read_exact_at(a, RING_HEADER + at).map_err(io)?;
        if !b.is_empty() {
            self.file.read_exact_at(b, RING_HEADER).map_err(io)?;
        }
        // The writer may have lapped the bytes while they were copied, published or not.
        self.lagged(self.word(32)?)?;
        let mut frames = Vec::new();
        let mut c = Cur(&self.buf);
        while !c.0.is_empty() {
            let at = self.tail + (n - c.0.len()) as u64;
            let len = c.u32().ok_or(RingError::Frame { at })?;
            let body = c.take(len as usize).ok_or(RingError::Frame { at })?;
            frames.push(RingFrame::decode(body).ok_or(RingError::Frame { at })?);
        }
        self.tail = head;
        let k = frames.len();
        frames.into_iter().for_each(&mut f);
        Ok(k)
    }
}

/// The [`DcOut`] of `vyrn-dropcopy`: writes into the server's store and wakes its sessions.
#[derive(Clone, Debug)]
pub struct StoreOut {
    pub store: Arc<RwLock<DcStore>>,
    pub wake: Arc<Wake>,
}

impl DcOut for StoreOut {
    fn push(&mut self, stream: StreamId, seq: u64, rec: &DcRecord) {
        if let Ok(mut s) = self.store.write() {
            s.push(stream, seq, rec);
        }
        self.wake.bump();
    }
}
