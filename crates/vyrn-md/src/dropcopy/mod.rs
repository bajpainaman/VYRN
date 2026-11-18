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
//! `flags.bit2` (durable) is always set: the observer replays only frames it holds from both
//! paths. The canonical stream is every record except `DC_FINAL` and `DC_SETTLED`; the last
//! `DC_EOD` carries the BLAKE3 hash of its canonical records before it, concatenated.
//!
//! **Not rebuilt yet:** `DC_REVERT` (replay has no revert path), `DC_SETTLED`, `DC_ALLOC` and
//! `DC_ROUTE` (no replay output carries them); the codec has them. Closing balances come from
//! the shell ([`Balances`]).

mod record;
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
    DC_DURABLE, DC_REC_BYTES, DC_SELL, DC_TAKER, DcOrder, DcRecord, DcRecordError, DcType,
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
    /// A record since the last `DC_FINAL`.
    fresh: bool,
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
            fresh: false,
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
    finals: VecDeque<(Height, StepId)>,
    /// The source of the last step and its taker fills so far (a `CONT` run).
    taker_acc: Option<((LaneId, LaneSeq), u32)>,
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
            finals: VecDeque::new(),
            taker_acc: None,
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
        self.flush_finals(false);
    }

    /// Ends the epoch: the pending `DC_FINAL`s, then each stream's `DC_EOD` records in stream
    /// order (10 §8.4 item 8). `balances` gives an account's closing balances.
    pub fn finish(mut self, balances: impl Fn(AccountId) -> Balances) -> Result<O, DcError> {
        if let Some(e) = self.err {
            return Err(e);
        }
        self.flush_finals(true);
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in ids {
            let mut b = Balances::default();
            for (a, x) in &self.accts {
                let member = if id.master {
                    *a == id.account || x.master == Some(id.account)
                } else {
                    *a == id.account
                };
                if member {
                    let c = balances(*a);
                    b.quote_free = b.quote_free.saturating_add(c.quote_free);
                    b.quote_resv = b.quote_resv.saturating_add(c.quote_resv);
                    b.base_free = b.base_free.saturating_add(c.base_free);
                    b.base_resv = b.base_resv.saturating_add(c.base_resv);
                }
            }
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
            self.push(id, &DcRecord::eod(acct, EOD_TOTALS, totals));
            self.push(id, &DcRecord::eod(acct, EOD_FEES, fees));
            let bal = [b.quote_free, b.quote_resv, b.base_free, b.base_resv, 0];
            self.push(id, &DcRecord::eod(acct, EOD_BALANCES, bal));
            let Some(s) = self.streams.get(&id) else {
                continue;
            };
            let h = *s.hasher.finalize().as_bytes();
            let r = DcRecord::eod_hash(acct, s.n, &h);
            self.push(id, &r);
        }
        Ok(self.out)
    }

    fn fail(&mut self, e: DcError) {
        if self.err.is_none() {
            self.err = Some(e);
        }
    }

    fn flush_finals(&mut self, all: bool) {
        while let Some(&(h, s)) = self.finals.front() {
            if !all && s > self.released {
                return;
            }
            self.finals.pop_front();
            let ids: Vec<StreamId> = self
                .streams
                .iter()
                .filter(|(_, x)| x.fresh)
                .map(|(k, _)| *k)
                .collect();
            for id in ids {
                let r = DcRecord::stage(DcType::Final, id.account, s, h);
                self.push(id, &r);
                if let Some(x) = self.streams.get_mut(&id) {
                    x.fresh = false;
                }
            }
        }
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
            s.hasher.update(&r.0);
            s.n += 1;
            s.fresh = true;
        }
        self.out.push(id, s.seq, r);
    }

    /// One record of `account` to each of its streams, with its fill totals.
    fn emit(&mut self, o: &DcOrder) -> Result<(), DcError> {
        let r = DcRecord::order(o);
        let n = if o.kind == DcType::Fill {
            self.notional(o.qty, o.tick)?
        } else {
            0
        };
        for id in self.targets(o.account).into_iter().flatten() {
            if let Some(s) = self.streams.get_mut(&id)
                && o.kind == DcType::Fill
            {
                s.fills = s.fills.checked_add(1).ok_or(DcError::Overflow)?;
                let (base, quote) = match o.side {
                    Side::Buy => (&mut s.base_bought, &mut s.quote_bought),
                    Side::Sell => (&mut s.base_sold, &mut s.quote_sold),
                };
                *base = base
                    .checked_add(u64::from(o.qty.0))
                    .ok_or(DcError::Overflow)?;
                *quote = quote.checked_add(n).ok_or(DcError::Overflow)?;
                s.fees = s.fees.checked_add(o.fee).ok_or(DcError::Overflow)?;
            }
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
                s.msg_fees = s
                    .msg_fees
                    .checked_add(u64::from(fee))
                    .ok_or(DcError::Overflow)?;
            }
        }
        Ok(())
    }

    fn on_lane_op(&mut self, op: &TapOp) -> Result<(), DcError> {
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
                self.orders.insert(
                    key(handle),
                    Resting {
                        account,
                        session: op.session,
                        side,
                        tick,
                        open: qty.0,
                        client_tag,
                    },
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
                let o = self.orders.get_mut(&key(handle)).ok_or(DcError::Order)?;
                o.open = o.open.checked_sub(canceled.0).ok_or(DcError::Order)?;
                let (side, tick) = (o.side, o.tick);
                if o.open == 0 {
                    self.orders.remove(&key(handle));
                }
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
                let o = self.orders.remove(&key(handle)).ok_or(DcError::Order)?;
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
                    let o = self.orders.get_mut(&mkey).ok_or(DcError::Order)?;
                    o.open = o.open.checked_sub(qty.0).ok_or(DcError::Order)?;
                    let m = *o;
                    if m.open == 0 {
                        self.orders.remove(&mkey);
                    }
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
                    let m = self
                        .orders
                        .remove(&(h.lane.0, handle.0))
                        .ok_or(DcError::Order)?;
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
                    self.orders.insert(
                        (src.lane.0, handle.0),
                        Resting {
                            account: taker_acct,
                            session: src.session,
                            side: tside,
                            tick,
                            open: left,
                            client_tag,
                        },
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
        self.taker_acc = Some((key, filled));
        Ok(())
    }
}

impl<O: DcOut> Tap for DropCopy<O> {
    fn lane_op(&mut self, op: &TapOp) {
        if self.err.is_some() {
            return;
        }
        if let Err(e) = self.on_lane_op(op) {
            self.fail(e);
        }
    }

    fn step(&mut self, st: &TapStep<'_>) {
        if self.err.is_some() {
            return;
        }
        if let Err(e) = self.on_step(st) {
            self.fail(e);
            return;
        }
        self.flush_finals(false);
    }
}
