//! Drop copy (10 §8): per-account streams of executions and order events, rebuilt from the
//! observer's replay and served over TCP.
//!
//! # Contract
//!
//! **Input.** [`DropCopy`] is a [`Tap`] of `vyrn-md`'s [`SinkStream`](crate::SinkStream): the
//! same sink adapter that rebuilds `MBO` hands it every resolved lane op and every released
//! step with its fill TX records, in the adapter's release order (10 §7.9 item 7). That order
//! is a function of the log, so live and replay give the same streams byte for byte, whatever
//! order the lanes' outputs interleaved in. The shell adds one call per block,
//! [`DropCopy::final_block`], once the block is final, and [`DropCopy::finish`] at epoch end.
//!
//! **Output.** One stream per account and one per master (all its sub-accounts and itself),
//! each a gapless sequence of 48-byte [`DcRecord`]s numbered from 1 per epoch, pushed to a
//! [`DcOut`]. Records (10 §8.4, each reading labeled there):
//!
//! | Replay output | Record |
//! |---|---|
//! | lane op `Ack` of a `New` | `DC_ACK`: `step` = its LaneSeq, `ordinal` = message index |
//! | lane op `CancelAck` (`Cancel`, `Reduce`) | `DC_CANCEL`, `qty` = canceled |
//! | lane op or step `Out` | `DC_OUT`; a step's carries its `StepId` |
//! | maker `Fill` `k` of step `s` | maker `DC_FILL` and the taker's `DC_FILL`, both `(s, k)` |
//! | taker `Ack` (residual) | `DC_ACK`: the source's LaneSeq, `qty` = what rests |
//! | any `Reject` | nothing: no order state changed |
//! | a final block | `DC_FINAL` on every stream that got a record since its last one |
//! | epoch end | `DC_EOD` totals, fees, balances, then the stream hash |
//!
//! | [`DropCopy::revert_after`] | `DC_REVERT` of every record after the kept step |
//! | [`DropCopy::alloc`] | `DC_ALLOC` after its control step |
//! | [`DropCopy::settled`] | `DC_SETTLED` on streams with unsettled final records |
//! | [`DropCopy::route`] | `DC_ROUTE` |
//!
//! `flags.bit2` (durable) is always set: the observer replays only frames it holds from both
//! paths. The canonical stream is the final records except `DC_FINAL`, `DC_SETTLED` and
//! `DC_REVERT`; the last `DC_EOD` carries the BLAKE3 hash of its canonical records before it.
//! Closing balances come from the shell ([`Balances`]).

pub mod noise;
mod record;
pub mod ring;
pub mod server;
pub mod wire;

use std::collections::{BTreeMap, VecDeque};

use vyrn_replica::sink::{OUT_STP, ROLE_MAKER, ROLE_TAKER, Record as Resp};
use vyrn_types::{
    AccountId, BookId, Handle, Height, LaneId, LaneSeq, Qty, SessionId, StepFlags, StepId,
    StepKind, Tick,
};
use vyrn_wire::Msg;

pub use record::{
    DC_DURABLE, DC_REC_BYTES, DC_SELL, DC_TAKER, DcOrder, DcRecord, DcRecordError, DcRoute, DcType,
    EOD_BALANCES, EOD_FEES, EOD_HASH, EOD_TOTALS,
};

use crate::record::Side;
use crate::replay::{Tap, TapOp, TapStep};

/// Epochs a stream can be replayed from: the current and the previous (10 §8.3, config).
pub const MD_DC_REPLAY_EPOCHS: usize = 2;
/// `StepEntry.flags` bit 0 (05 §4.15).
const STEP_CONT: u8 = 1;
/// `RSK_FEE_DENOM` (10 §5.1).
const FEE_DENOM: u128 = 1_000_000;

/// A stream: an account's own, or a master's (`master`), which carries every record of its
/// sub-accounts and of the master account itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId {
    pub account: AccountId,
    pub master: bool,
}

/// One account as the drop copy needs it: its sessions, master and fee rates (10 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcAccount {
    pub account: AccountId,
    pub master: Option<AccountId>,
    pub sessions: Vec<SessionId>,
    pub taker_ppm: i32,
    pub maker_ppm: i32,
    pub msg_fee_improve: u32,
    pub msg_fee_cross: u32,
}

/// The book and its accounts for one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcConfig {
    pub book: BookId,
    /// Quote units per lot per tick (10 §2.1).
    pub tick_size: u64,
    pub accounts: Vec<DcAccount>,
}

/// Closing balances of an account in the book (10 §8.3), from the replayed engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balances {
    pub quote_free: u64,
    pub quote_resv: u64,
    pub base_free: u64,
    pub base_resv: u64,
}

/// Where records go, in stream order. `seq` is the record's stream sequence (from 1).
pub trait DcOut {
    fn push(&mut self, stream: StreamId, seq: u64, rec: &DcRecord);
}

impl DcOut for Vec<(StreamId, u64, DcRecord)> {
    fn push(&mut self, stream: StreamId, seq: u64, rec: &DcRecord) {
        self.push((stream, seq, *rec));
    }
}

/// Why the drop copy stopped. After the first error it ignores every later call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcError {
    /// A record names an order the rebuilt state does not hold, or fills more than is open.
    Order,
    /// The taker's fills per level do not sum to the makers' fills at that level.
    Fills,
    /// An accumulator overflowed.
    Overflow,
    /// A case this version does not rebuild.
    Unsupported(&'static str),
    /// A revert that reaches a final step, or a call that the epoch's end ruled out.
    Final,
}

#[derive(Clone, Copy, Debug)]
struct Acct {
    master: Option<AccountId>,
    taker_ppm: i32,
    maker_ppm: i32,
    msg_improve: u32,
    msg_cross: u32,
}

#[derive(Clone, Debug)]
struct Stream {
    seq: u64,
    /// Canonical records hashed so far.
    n: u64,
    hasher: blake3::Hasher,
    fills: u64,
    base_bought: u64,
    base_sold: u64,
    quote_bought: u64,
    quote_sold: u64,
    fees: i64,
    msg_fees: u64,
    /// Canonical records and message fees no `DC_FINAL` covers yet, with their release steps.
    /// They are hashed and totalled when one does, and a revert drops them (10 §8.4 item 3).
    pend: VecDeque<(u64, Pend)>,
    /// Release steps of final canonical records no `DC_SETTLED` covers yet, deduplicated.
    unsettled: VecDeque<u64>,
}

/// What a stream holds until it is final.
#[derive(Clone, Copy, Debug)]
enum Pend {
    Rec(DcRecord),
    MsgFee(u64),
}

/// The state a revert restores (10 §8.4 item 9).
#[derive(Clone, Copy, Debug)]
enum Undo {
    Order((u8, u32), Option<Resting>),
    Taker(Option<((LaneId, LaneSeq), u32)>),
}

/// The asset of a `DC_ALLOC` (byte 1 of `CtlAllocCredit`, 10 §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocAsset {
    Quote = 0,
    Base = 1,
}

/// One allocation reply of the control path (`AllocCredited` / `AllocDebited`, 10 §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alloc {
    /// The control step that applied it.
    pub step: StepId,
    pub account: AccountId,
    pub asset: AllocAsset,
    pub debit: bool,
    /// Credited, or actually debited (`min(amount, free)`).
    pub amount: u64,
}

impl Stream {
    fn new() -> Self {
        Self {
            seq: 0,
            n: 0,
            hasher: blake3::Hasher::new(),
            fills: 0,
            base_bought: 0,
            base_sold: 0,
            quote_bought: 0,
            quote_sold: 0,
            fees: 0,
            msg_fees: 0,
            pend: VecDeque::new(),
            unsettled: VecDeque::new(),
        }
    }
}

/// A resting order as the drop copy knows it.
#[derive(Clone, Copy, Debug)]
struct Resting {
    account: Option<AccountId>,
    session: SessionId,
    side: Side,
    tick: Tick,
    open: u32,
    client_tag: u32,
}

/// The drop copy of one book and one epoch (module docs).
pub struct DropCopy<O: DcOut> {
    tick_size: u64,
    sessions: BTreeMap<SessionId, AccountId>,
    accts: BTreeMap<AccountId, Acct>,
    streams: BTreeMap<StreamId, Stream>,
    orders: BTreeMap<(u8, u32), Resting>,
    released: StepId,
    /// The release step of the records being emitted: the step whose release carries them.
    rel: u64,
    finals: VecDeque<(Height, StepId)>,
    /// The newest step a `DC_FINAL` covers: no revert reaches it.
    final_step: StepId,
    /// The newest `DC_FINAL` sent, for an allocation of its block that comes after it.
    last_final: Option<(Height, StepId)>,
    /// Allocations waiting for their control step's release.
    allocs: VecDeque<Alloc>,
    /// Order-state changes of steps no `DC_FINAL` covers yet, with their release steps.
    undo: VecDeque<(u64, Undo)>,
    /// The source of the last step and its taker fills so far (a `CONT` run).
    taker_acc: Option<((LaneId, LaneSeq), u32)>,
    /// `DC_EOD` is out: only `DC_SETTLED` may follow.
    ended: bool,
    out: O,
    err: Option<DcError>,
}

const fn side_of(s: vyrn_wire::Side) -> Side {
    match s {
        vyrn_wire::Side::Buy => Side::Buy,
        vyrn_wire::Side::Sell => Side::Sell,
    }
}

const fn opposite(s: Side) -> Side {
    match s {
        Side::Buy => Side::Sell,
        Side::Sell => Side::Buy,
    }
}

/// The fee of notional `n` at `ppm` (10 §3.3): `ceil` for a charge, `−floor` for a rebate.
fn fee_of(n: u128, ppm: i32) -> Option<i64> {
    let x = n.checked_mul(u128::from(ppm.unsigned_abs()))?;
    if ppm >= 0 {
        i64::try_from(x.div_ceil(FEE_DENOM)).ok()
    } else {
        i64::try_from(x / FEE_DENOM).ok()?.checked_neg()
    }
}

impl<O: DcOut> DropCopy<O> {
    pub fn new(cfg: &DcConfig, out: O) -> Self {
        let mut sessions = BTreeMap::new();
        let mut accts = BTreeMap::new();
        let mut streams = BTreeMap::new();
        for a in &cfg.accounts {
            for s in &a.sessions {
                sessions.insert(*s, a.account);
            }
            accts.insert(
                a.account,
                Acct {
                    master: a.master.filter(|m| *m != a.account),
                    taker_ppm: a.taker_ppm,
                    maker_ppm: a.maker_ppm,
                    msg_improve: a.msg_fee_improve,
                    msg_cross: a.msg_fee_cross,
                },
            );
            streams.insert(
                StreamId {
                    account: a.account,
                    master: false,
                },
                Stream::new(),
            );
            if let Some(m) = a.master {
                streams.insert(
                    StreamId {
                        account: m,
                        master: true,
                    },
                    Stream::new(),
                );
            }
        }
        Self {
            tick_size: cfg.tick_size,
            sessions,
            accts,
            streams,
            orders: BTreeMap::new(),
            released: StepId(0),
            rel: 0,
            finals: VecDeque::new(),
            final_step: StepId(0),
            last_final: None,
            allocs: VecDeque::new(),
            undo: VecDeque::new(),
            taker_acc: None,
            ended: false,
            out,
            err: None,
        }
    }

    pub fn error(&self) -> Option<DcError> {
        self.err
    }

    pub fn out(&self) -> &O {
        &self.out
    }

    pub fn out_mut(&mut self) -> &mut O {
        &mut self.out
    }

    /// The streams this drop copy writes, in order.
    pub fn streams(&self) -> impl Iterator<Item = StreamId> + '_ {
        self.streams.keys().copied()
    }

    /// Block `height`, whose last step is `last_step`, is final (`INV-QUORUM`). Its `DC_FINAL`
    /// goes out once every step up to `last_step` is released (10 §8.4 item 7).
    pub fn final_block(&mut self, height: Height, last_step: StepId) {
        if self.err.is_some() {
            return;
        }
        self.finals.push_back((height, last_step));
        if let Err(e) = self.flush_finals(false) {
            self.fail(e);
        }
    }

    /// An allocation reply of the control path (10 §2.5). It goes out right after its control
    /// step's records, once that step is released (10 §8.4 item 10).
    pub fn alloc(&mut self, a: Alloc) {
        if self.err.is_some() {
            return;
        }
        if self.ended {
            return self.fail(DcError::Final);
        }
        self.allocs.push_back(a);
        // An allocation of a step whose block's DC_FINAL went out already gets that DC_FINAL
        // again in its streams, after it (10 §8.4 item 10).
        let r = self
            .flush_allocs(self.released)
            .and_then(|()| match self.last_final {
                Some((h, s)) => self.final_to(h, s),
                None => Ok(()),
            });
        if let Err(e) = r {
            self.fail(e);
        }
    }

    /// An accepted `RouteMove` (10 §2.8). The engine has no route op yet, so the shell hands it
    /// over at its position in its interval, as a [`Tap::lane_op`] would be; it is released
    /// with the step that closes the interval (10 §8.4 item 12).
    pub fn route(&mut self, r: &DcRoute) {
        if self.err.is_some() {
            return;
        }
        if self.ended {
            return self.fail(DcError::Final);
        }
        self.rel = self.released.0.saturating_add(1);
        let rec = DcRecord::route(r);
        for id in self.targets(r.account).into_iter().flatten() {
            self.push(id, &rec);
        }
    }

    /// Steps after `kept` are not in the final log (07 §9.6; a deposed tenure's seal stops at
    /// `kept`). Every record released after `kept` gets a `DC_REVERT`, in stream order, and the
    /// order state goes back to just after `kept`, so the replay of the final log continues from
    /// there (10 §8.4 item 9). `kept` must be at least the newest final step.
    pub fn revert_after(&mut self, kept: StepId) {
        if self.err.is_some() {
            return;
        }
        if self.ended || kept < self.final_step {
            return self.fail(DcError::Final);
        }
        let k = kept.0;
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in ids {
            let Some(st) = self.streams.get_mut(&id) else {
                continue;
            };
            let at = st
                .pend
                .iter()
                .position(|(r, _)| *r > k)
                .unwrap_or(st.pend.len());
            let gone: Vec<(u64, Pend)> = st.pend.drain(at..).collect();
            for (_, p) in gone {
                if let Pend::Rec(r) = p {
                    self.push(id, &DcRecord::revert(&r));
                }
            }
        }
        while self.undo.back().is_some_and(|(r, _)| *r > k) {
            match self.undo.pop_back() {
                Some((_, Undo::Order(key, Some(o)))) => {
                    self.orders.insert(key, o);
                }
                Some((_, Undo::Order(key, None))) => {
                    self.orders.remove(&key);
                }
                Some((_, Undo::Taker(t))) => self.taker_acc = t,
                None => {}
            }
        }
        self.allocs.retain(|a| a.step <= kept);
        self.finals.retain(|f| f.1 <= kept);
        self.released = self.released.min(kept);
        self.rel = self.released.0;
    }

    /// Block `height`, whose last step is `last_step`, is settled (`BASE`: the ledger credited
    /// the epoch statement, 10 §10; `CHAIN`: 09's settlement covers it). Every stream holding a
    /// final record released at a step ≤ `last_step` that no `DC_SETTLED` covers gets one. It may
    /// come after the epoch's `DC_EOD` (10 §8.4 item 11).
    pub fn settled(&mut self, height: Height, last_step: StepId) {
        if self.err.is_some() {
            return;
        }
        if last_step > self.final_step {
            return self.fail(DcError::Final);
        }
        let ids: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|(_, x)| x.unsettled.front().is_some_and(|r| *r <= last_step.0))
            .map(|(k, _)| *k)
            .collect();
        for id in ids {
            if let Some(x) = self.streams.get_mut(&id) {
                while x.unsettled.front().is_some_and(|r| *r <= last_step.0) {
                    x.unsettled.pop_front();
                }
            }
            self.push(
                id,
                &DcRecord::stage(DcType::Settled, id.account, last_step, height),
            );
        }
    }

    /// Ends the epoch and hands back the output ([`DropCopy::end_epoch`], then the output).
    pub fn finish(mut self, balances: impl Fn(AccountId) -> Balances) -> Result<O, DcError> {
        self.end_epoch(balances)?;
        Ok(self.out)
    }

    /// Hands back the output; after [`DropCopy::end_epoch`] and any `DC_SETTLED`.
    pub fn into_out(self) -> Result<O, DcError> {
        match self.err {
            Some(e) => Err(e),
            None => Ok(self.out),
        }
    }

    /// Ends the epoch: the pending allocations and `DC_FINAL`s (the epoch's end makes every
    /// released step final), then each stream's `DC_EOD` records in stream order (10 §8.4
    /// item 8). `balances` gives an account's closing balances.
    pub fn end_epoch(&mut self, balances: impl Fn(AccountId) -> Balances) -> Result<(), DcError> {
        if let Some(e) = self.err {
            return Err(e);
        }
        if self.ended {
            return Err(DcError::Final);
        }
        self.flush_allocs(StepId(u64::MAX))?;
        self.flush_finals(true)?;
        // Records no block's DC_FINAL covered are final with the epoch.
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in &ids {
            self.commit_upto(*id, u64::MAX)?;
        }
        self.undo.clear();
        // The epoch's end makes every released step final, so they can settle.
        self.final_step = self.final_step.max(self.released);
        self.ended = true;
        // Each account's balance once, into its own stream and its master's (10 §8.4 item 6).
        let mut bal: BTreeMap<StreamId, Balances> = BTreeMap::new();
        for (a, x) in &self.accts {
            let c = balances(*a);
            let own = StreamId {
                account: *a,
                master: false,
            };
            let mine = StreamId {
                account: *a,
                master: true,
            };
            let master = x.master.map(|m| StreamId {
                account: m,
                master: true,
            });
            for id in [Some(own), Some(mine), master].into_iter().flatten() {
                if self.streams.contains_key(&id) {
                    let b = bal.entry(id).or_default();
                    let add = |x: u64, y: u64| x.checked_add(y).ok_or(DcError::Overflow);
                    b.quote_free = add(b.quote_free, c.quote_free)?;
                    b.quote_resv = add(b.quote_resv, c.quote_resv)?;
                    b.base_free = add(b.base_free, c.base_free)?;
                    b.base_resv = add(b.base_resv, c.base_resv)?;
                }
            }
        }
        self.rel = self.released.0;
        for id in ids {
            let b = bal.get(&id).copied().unwrap_or_default();
            let Some(s) = self.streams.get(&id) else {
                continue;
            };
            let totals = [
                s.fills,
                s.base_bought,
                s.base_sold,
                s.quote_bought,
                s.quote_sold,
            ];
            // Two's complement: a net rebate reads back as a negative i64.
            #[allow(clippy::cast_sign_loss, clippy::as_conversions)]
            let fees = [s.fees as u64, s.msg_fees, 0, 0, 0];
            let acct = id.account;
            let bal = [b.quote_free, b.quote_resv, b.base_free, b.base_resv, 0];
            for r in [
                DcRecord::eod(acct, EOD_TOTALS, totals),
                DcRecord::eod(acct, EOD_FEES, fees),
                DcRecord::eod(acct, EOD_BALANCES, bal),
            ] {
                self.push(id, &r);
                self.commit_upto(id, u64::MAX)?;
            }
            let Some(s) = self.streams.get(&id) else {
                continue;
            };
            let h = *s.hasher.finalize().as_bytes();
            let r = DcRecord::eod_hash(acct, s.n, &h);
            self.push(id, &r);
            self.commit_upto(id, u64::MAX)?;
        }
        Ok(())
    }

    fn fail(&mut self, e: DcError) {
        if self.err.is_none() {
            self.err = Some(e);
        }
    }

    /// Sends each due `DC_FINAL(s)` to every stream holding a record released at a step ≤ `s`
    /// that no earlier `DC_FINAL` covers, and makes those records canonical (10 §8.4 item 7).
    fn flush_finals(&mut self, all: bool) -> Result<(), DcError> {
        while let Some(&(h, s)) = self.finals.front() {
            if !all && s > self.released {
                return Ok(());
            }
            self.finals.pop_front();
            self.final_step = self.final_step.max(s);
            self.last_final = Some((h, s));
            while self.undo.front().is_some_and(|(r, _)| *r <= s.0) {
                self.undo.pop_front();
            }
            self.final_to(h, s)?;
        }
        Ok(())
    }

    /// `DC_FINAL(s)` to every stream holding a record released at a step ≤ `s` that no
    /// earlier `DC_FINAL` covers; those records become canonical.
    fn final_to(&mut self, h: Height, s: StepId) -> Result<(), DcError> {
        let ids: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|(_, x)| x.pend.front().is_some_and(|(r, _)| *r <= s.0))
            .map(|(k, _)| *k)
            .collect();
        for id in ids {
            self.commit_upto(id, s.0)?;
            let r = DcRecord::stage(DcType::Final, id.account, s, h);
            self.push(id, &r);
        }
        Ok(())
    }

    /// Hashes and totals every pending entry of `id` released at a step ≤ `upto`.
    fn commit_upto(&mut self, id: StreamId, upto: u64) -> Result<(), DcError> {
        let ts = self.tick_size;
        let Some(s) = self.streams.get_mut(&id) else {
            return Ok(());
        };
        while let Some(&(rel, p)) = s.pend.front().filter(|(r, _)| *r <= upto) {
            s.pend.pop_front();
            if s.unsettled.back() != Some(&rel) {
                s.unsettled.push_back(rel);
            }
            let r = match p {
                Pend::MsgFee(f) => {
                    s.msg_fees = s.msg_fees.checked_add(f).ok_or(DcError::Overflow)?;
                    continue;
                }
                Pend::Rec(r) => r,
            };
            s.hasher.update(&r.0);
            s.n += 1;
            if r.kind() != DcType::Fill {
                continue;
            }
            let n = u64::from(r.qty().0)
                .checked_mul(u64::from(r.tick().0))
                .and_then(|x| x.checked_mul(ts))
                .ok_or(DcError::Overflow)?;
            s.fills = s.fills.checked_add(1).ok_or(DcError::Overflow)?;
            let (base, quote) = match r.side() {
                Side::Buy => (&mut s.base_bought, &mut s.quote_bought),
                Side::Sell => (&mut s.base_sold, &mut s.quote_sold),
            };
            *base = base
                .checked_add(u64::from(r.qty().0))
                .ok_or(DcError::Overflow)?;
            *quote = quote.checked_add(n).ok_or(DcError::Overflow)?;
            s.fees = s.fees.checked_add(r.fee()).ok_or(DcError::Overflow)?;
        }
        Ok(())
    }

    /// Sends the allocations of control steps up to `upto`, each after its step's records.
    fn flush_allocs(&mut self, upto: StepId) -> Result<(), DcError> {
        while let Some(a) = self.allocs.front().copied().filter(|a| a.step <= upto) {
            self.allocs.pop_front();
            self.rel = a.step.0;
            let r = DcRecord::alloc(a.account, a.step, a.asset as u8, a.debit, a.amount);
            for id in self.targets(a.account).into_iter().flatten() {
                self.push(id, &r);
            }
        }
        Ok(())
    }

    fn set_order(&mut self, key: (u8, u32), o: Option<Resting>) {
        let old = match o {
            Some(o) => self.orders.insert(key, o),
            None => self.orders.remove(&key),
        };
        self.undo.push_back((self.rel, Undo::Order(key, old)));
    }

    fn set_taker(&mut self, t: Option<((LaneId, LaneSeq), u32)>) {
        let old = std::mem::replace(&mut self.taker_acc, t);
        self.undo.push_back((self.rel, Undo::Taker(old)));
    }

    /// The streams a record of `account` goes to: its own, its master's, and its own master
    /// stream when it is a master.
    fn targets(&self, account: AccountId) -> [Option<StreamId>; 3] {
        let own = StreamId {
            account,
            master: false,
        };
        let master = self
            .accts
            .get(&account)
            .and_then(|a| a.master)
            .map(|m| StreamId {
                account: m,
                master: true,
            });
        let me = StreamId {
            account,
            master: true,
        };
        [
            self.streams.contains_key(&own).then_some(own),
            master,
            self.streams.contains_key(&me).then_some(me),
        ]
    }

    fn push(&mut self, id: StreamId, r: &DcRecord) {
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        s.seq += 1;
        if !r.kind().is_stage() {
            s.pend.push_back((self.rel, Pend::Rec(*r)));
        }
        self.out.push(id, s.seq, r);
    }

    /// One record of `account` to each of its streams.
    fn emit(&mut self, o: &DcOrder) -> Result<(), DcError> {
        let r = DcRecord::order(o);
        for id in self.targets(o.account).into_iter().flatten() {
            self.push(id, &r);
        }
        Ok(())
    }

    fn notional(&self, q: Qty, t: Tick) -> Result<u64, DcError> {
        u64::from(q.0)
            .checked_mul(u64::from(t.0))
            .and_then(|x| x.checked_mul(self.tick_size))
            .ok_or(DcError::Overflow)
    }

    fn charge_msg_fee(&mut self, account: AccountId, fee: u32) -> Result<(), DcError> {
        for id in self.targets(account).into_iter().flatten() {
            if let Some(s) = self.streams.get_mut(&id) {
                s.pend.push_back((self.rel, Pend::MsgFee(u64::from(fee))));
            }
        }
        Ok(())
    }

    fn on_lane_op(&mut self, op: &TapOp) -> Result<(), DcError> {
        // A lane op is released with the step that closes its interval.
        self.rel = self.released.0.saturating_add(1);
        let account = self.sessions.get(&op.session).copied();
        let key = |h: Handle| (op.lane.0, h.0);
        let base = |kind, side, handle: Handle, tick, qty, client_tag, index| DcOrder {
            kind,
            side,
            taker: false,
            ordinal: u16::from(index),
            account: account.unwrap_or(AccountId(0)),
            step: op.seq.0,
            session: op.session,
            resp_seq: op.resp_seq,
            handle,
            tick,
            qty,
            client_tag,
            fee: 0,
        };
        let rec = match (op.msg, op.rec) {
            (
                Some(Msg::New { flags, qty, .. }),
                Resp::Ack {
                    index,
                    handle,
                    tick,
                    client_tag,
                },
            ) => {
                let side = side_of(flags.side);
                self.set_order(
                    key(handle),
                    Some(Resting {
                        account,
                        session: op.session,
                        side,
                        tick,
                        open: qty.0,
                        client_tag,
                    }),
                );
                base(DcType::Ack, side, handle, tick, qty, client_tag, index)
            }
            (
                Some(Msg::Cancel { .. } | Msg::Reduce { .. }),
                Resp::CancelAck {
                    index,
                    handle,
                    canceled,
                    client_tag,
                },
            ) => {
                let mut o = *self.orders.get(&key(handle)).ok_or(DcError::Order)?;
                o.open = o.open.checked_sub(canceled.0).ok_or(DcError::Order)?;
                let (side, tick) = (o.side, o.tick);
                self.set_order(key(handle), (o.open != 0).then_some(o));
                base(
                    DcType::Cancel,
                    side,
                    handle,
                    tick,
                    canceled,
                    client_tag,
                    index,
                )
            }
            (
                _,
                Resp::Out {
                    index,
                    handle,
                    qty,
                    client_tag,
                    ..
                },
            ) => {
                let o = *self.orders.get(&key(handle)).ok_or(DcError::Order)?;
                self.set_order(key(handle), None);
                base(DcType::Out, o.side, handle, o.tick, qty, client_tag, index)
            }
            (_, Resp::Reject { .. }) => return Ok(()),
            _ => return Err(DcError::Unsupported("lane record")),
        };
        if account.is_some() {
            self.emit(&rec)?;
        }
        Ok(())
    }

    fn on_step(&mut self, st: &TapStep<'_>) -> Result<(), DcError> {
        self.released = st.step;
        self.rel = st.step.0;
        let Some(src) = st.src else {
            if st.tx.iter().any(|(_, r)| !matches!(r, Resp::Reject { .. })) {
                return Err(DcError::Unsupported("records of a step without a source"));
            }
            return Ok(());
        };
        let Some(Msg::New {
            flags,
            tick: limit,
            qty,
            client_tag,
        }) = src.msg
        else {
            return Err(DcError::Unsupported("step source other than New"));
        };
        let taker_acct = self.sessions.get(&src.session).copied();
        let tside = side_of(flags.side);
        // 10 §5.3: an accepted forwarded New pays its class once, at its first step; a shed
        // owes nothing (§3.11).
        if st.flags & STEP_CONT == 0
            && st.kind != StepKind::Shed
            && let Some(a) = taker_acct
            && let Some(x) = self.accts.get(&a).copied()
        {
            let fee = if st.flags & StepFlags::CROSS != 0 {
                x.msg_cross
            } else {
                x.msg_improve
            };
            self.charge_msg_fee(a, fee)?;
        }
        let taker_hdr = st
            .tx
            .iter()
            .find(|(h, _)| h.role == ROLE_TAKER)
            .map(|x| x.0);
        let taker_handle = st.tx.iter().find_map(|(h, r)| match *r {
            Resp::Fill { handle, .. } | Resp::Ack { handle, .. } | Resp::Out { handle, .. }
                if h.role == ROLE_TAKER =>
            {
                Some(handle)
            }
            _ => None,
        });
        // The maker fills, which are the matches, against the taker's fills per level.
        let mut levels: BTreeMap<u32, i64> = BTreeMap::new();
        let mut n_match = 0usize;
        let mut taker_n = 0u128;
        for (h, r) in st.tx {
            match (h.role, *r) {
                (ROLE_MAKER, Resp::Fill { tick, qty, .. }) => {
                    *levels.entry(tick.0).or_default() += i64::from(qty.0);
                    n_match += 1;
                    taker_n += u128::from(self.notional(qty, tick)?);
                }
                (ROLE_TAKER, Resp::Fill { tick, qty, .. }) => {
                    *levels.entry(tick.0).or_default() -= i64::from(qty.0);
                }
                _ => {}
            }
        }
        if levels.values().any(|v| *v != 0) {
            return Err(DcError::Fills);
        }
        let taker_fee = match taker_acct.and_then(|a| self.accts.get(&a)) {
            Some(x) => fee_of(taker_n, x.taker_ppm).ok_or(DcError::Overflow)?,
            None => 0,
        };
        let key = (src.lane, src.seq);
        let mut filled = match self.taker_acc {
            Some((k, q)) if k == key => q,
            _ => 0,
        };
        let mut k = 0u16;
        for (h, r) in st.tx {
            if h.role != ROLE_MAKER {
                continue;
            }
            match *r {
                Resp::Fill {
                    handle, tick, qty, ..
                } => {
                    let mkey = (h.lane.0, handle.0);
                    let mut m = *self.orders.get(&mkey).ok_or(DcError::Order)?;
                    m.open = m.open.checked_sub(qty.0).ok_or(DcError::Order)?;
                    self.set_order(mkey, (m.open != 0).then_some(m));
                    if opposite(m.side) != tside {
                        return Err(DcError::Order);
                    }
                    filled = filled.checked_add(qty.0).ok_or(DcError::Overflow)?;
                    let last = usize::from(k) + 1 == n_match;
                    if let (Some(a), Some(th), Some(hd)) = (taker_acct, taker_handle, taker_hdr) {
                        self.emit(&DcOrder {
                            kind: DcType::Fill,
                            side: tside,
                            taker: true,
                            ordinal: k,
                            account: a,
                            step: st.step.0,
                            session: src.session,
                            resp_seq: hd.resp_seq,
                            handle: th,
                            tick,
                            qty,
                            client_tag,
                            fee: if last { taker_fee } else { 0 },
                        })?;
                    }
                    if let Some(a) = m.account {
                        let n = u128::from(self.notional(qty, tick)?);
                        let ppm = self.accts.get(&a).map_or(0, |x| x.maker_ppm);
                        self.emit(&DcOrder {
                            kind: DcType::Fill,
                            side: m.side,
                            taker: false,
                            ordinal: k,
                            account: a,
                            step: st.step.0,
                            session: m.session,
                            resp_seq: h.resp_seq,
                            handle,
                            tick,
                            qty,
                            client_tag: m.client_tag,
                            fee: fee_of(n, ppm).ok_or(DcError::Overflow)?,
                        })?;
                    }
                    k += 1;
                }
                Resp::Out {
                    index,
                    cause: OUT_STP,
                    handle,
                    qty,
                    client_tag,
                } => {
                    let mkey = (h.lane.0, handle.0);
                    let m = *self.orders.get(&mkey).ok_or(DcError::Order)?;
                    self.set_order(mkey, None);
                    if let Some(a) = m.account {
                        self.emit(&DcOrder {
                            kind: DcType::Out,
                            side: m.side,
                            taker: false,
                            ordinal: u16::from(index),
                            account: a,
                            step: st.step.0,
                            session: m.session,
                            resp_seq: h.resp_seq,
                            handle,
                            tick: m.tick,
                            qty,
                            client_tag,
                            fee: 0,
                        })?;
                    }
                }
                Resp::Reject { .. } => {}
                _ => return Err(DcError::Unsupported("maker record")),
            }
        }
        for (h, r) in st.tx {
            if h.role != ROLE_TAKER {
                continue;
            }
            match *r {
                Resp::Ack {
                    index,
                    handle,
                    tick,
                    client_tag,
                } => {
                    let left = qty.0.checked_sub(filled).ok_or(DcError::Order)?;
                    self.set_order(
                        (src.lane.0, handle.0),
                        Some(Resting {
                            account: taker_acct,
                            session: src.session,
                            side: tside,
                            tick,
                            open: left,
                            client_tag,
                        }),
                    );
                    if let Some(a) = taker_acct {
                        self.emit(&DcOrder {
                            kind: DcType::Ack,
                            side: tside,
                            taker: false,
                            ordinal: u16::from(index),
                            account: a,
                            step: src.seq.0,
                            session: src.session,
                            resp_seq: h.resp_seq,
                            handle,
                            tick,
                            qty: Qty(left),
                            client_tag,
                            fee: 0,
                        })?;
                    }
                }
                Resp::Out {
                    index,
                    handle,
                    qty: out,
                    client_tag,
                    ..
                } => {
                    if let Some(a) = taker_acct {
                        self.emit(&DcOrder {
                            kind: DcType::Out,
                            side: tside,
                            taker: true,
                            ordinal: u16::from(index),
                            account: a,
                            step: st.step.0,
                            session: src.session,
                            resp_seq: h.resp_seq,
                            handle,
                            tick: limit,
                            qty: out,
                            client_tag,
                            fee: 0,
                        })?;
                    }
                }
                Resp::Fill { .. } | Resp::Reject { .. } => {}
                Resp::CancelAck { .. } => return Err(DcError::Unsupported("taker record")),
            }
        }
        self.set_taker(Some((key, filled)));
        Ok(())
    }
}

impl<O: DcOut> Tap for DropCopy<O> {
    fn lane_op(&mut self, op: &TapOp) {
        if self.err.is_some() {
            return;
        }
        if self.ended {
            return self.fail(DcError::Final);
        }
        if let Err(e) = self.on_lane_op(op) {
            self.fail(e);
        }
    }

    fn step(&mut self, st: &TapStep<'_>) {
        if self.err.is_some() {
            return;
        }
        if self.ended {
            return self.fail(DcError::Final);
        }
        let r = self
            .on_step(st)
            .and_then(|()| self.flush_allocs(st.step))
            .and_then(|()| self.flush_finals(false));
        if let Err(e) = r {
            self.fail(e);
        }
    }
}
