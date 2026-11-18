//! `VxReplay`: [`ReplayEngine`] over `libvyrn_vx_client` (11 §5.3), the Vx replay engine.
//!
//! # Contract
//!
//! **Input** is [`crate::RustReplay`]'s: one [`BlockInputs`] per block in height order, on one
//! client started from the tenure's initial state ([`VxConfig`]), with every packet's payload in
//! `P`. The shell writes each lane's records to that lane's input ring in O-order, a packet's
//! route records in its slot, and the steps to the step ring; the client merges them by 07 §7.1
//! `REP_MERGE` and itself holds the records of a lane that are not due yet (its ring keeps them),
//! so the shell carries nothing.
//!
//! **Done.** A block is complete once the BBO replayer has run its last step and every lane has
//! either replayed all its records or waits on a later step. The outputs then drained are the
//! block's, and [`BlockOutputs::output_hash`] is [`crate::output_hash`] over them: the client
//! writes each response and TX packet in exactly the bytes `encode_resp` and `encode_tx` hash.
//!
//! **Rejects.** Any `PBV_E_*` word the client raises (a divergence, or a case outside v1's
//! subset, pbv.h), an `AcctTake`, a missing payload, and `load_snapshot`/`write_state`.

// Offsets are bounded by the region (`pbv_shared_bytes`, at most 64 lanes) and counters count
// records, so this module's arithmetic cannot overflow; its indexing is by lane, below `N`.
#![allow(clippy::arithmetic_side_effects)]

use core::sync::atomic::Ordering;
use std::path::Path;

use vyrn_engine::Payloads;
use vyrn_log::LaneRec;
use vyrn_types::{PacketFlags, PacketRecord, RouteRecord};

use crate::ports::{
    BlockInputs, BlockOutputs, CanonicalStateWriter, ReplayEngine, ReplayError, StateSnapshot,
};
use crate::vx::{Client, Line};

// pbv.h client geometry.
const SLOTS: u64 = 1024;
const IN_BYTES: usize = 512;
const OUT_BYTES: usize = 288;
const STEP_BYTES: usize = 576;
const TX_BYTES: usize = 288;
const IN_ROUTES: usize = 64;
const MAX_ROUTES: usize = 10;
const IN_PAYLOAD: usize = 224;
const ERRS: [&str; 10] = [
    "",
    "mismatch",
    "order",
    "source",
    "kind",
    "cut",
    "too old",
    "bad record",
    "unsupported",
    "fault",
];

/// One account (pbv.h `pbv_account`).
#[derive(Clone, Copy, Debug, Default)]
pub struct VxAccount {
    pub slot: u32,
    pub lane: u8,
    /// 0 active, 1 killed, 2 closed.
    pub state: u8,
    pub max_open: u32,
    pub max_qty: u32,
    pub max_notional: u64,
    pub taker_ppm: i32,
    pub maker_ppm: i32,
    pub auction_ppm: i32,
    pub msg_fee_improve: u32,
    pub msg_fee_cross: u32,
    pub base_free: u64,
    pub quote_free: u128,
}

/// One session (pbv.h `pbv_session`).
#[derive(Clone, Copy, Debug, Default)]
pub struct VxSession {
    pub id: u32,
    pub acct: u32,
    pub book: u16,
    pub k_seq: [u8; 16],
}

/// The tenure's initial state for the client (pbv.h `pbv_config` and its tables).
#[derive(Clone, Debug, Default)]
pub struct VxConfig {
    pub n_lanes: u8,
    pub book: u16,
    pub epoch: u32,
    pub tick_min: u32,
    pub tick_max: u32,
    pub tick_size: u64,
    pub band_bps: u32,
    pub slot_cap: u32,
    pub seg_cap: u32,
    pub accounts: Vec<VxAccount>,
    pub sessions: Vec<VxSession>,
}

impl VxConfig {
    fn tables(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut c = vec![0u8; 64];
        put(&mut c, 0, &2u32.to_le_bytes());
        put(&mut c, 4, &64u32.to_le_bytes());
        put(&mut c, 8, &[self.n_lanes]);
        put(&mut c, 10, &self.book.to_le_bytes());
        put(&mut c, 12, &self.epoch.to_le_bytes());
        put(&mut c, 16, &self.tick_min.to_le_bytes());
        put(&mut c, 20, &self.tick_max.to_le_bytes());
        put(&mut c, 24, &self.tick_size.to_le_bytes());
        put(&mut c, 32, &self.band_bps.to_le_bytes());
        put(&mut c, 36, &self.slot_cap.to_le_bytes());
        put(&mut c, 40, &self.seg_cap.to_le_bytes());
        let mut a = Vec::new();
        for x in &self.accounts {
            let mut b = vec![0u8; 80];
            put(&mut b, 0, &x.slot.to_le_bytes());
            put(&mut b, 4, &[x.lane, x.state]);
            put(&mut b, 8, &x.max_open.to_le_bytes());
            put(&mut b, 12, &x.max_qty.to_le_bytes());
            put(&mut b, 16, &x.max_notional.to_le_bytes());
            put(&mut b, 24, &x.taker_ppm.to_le_bytes());
            put(&mut b, 28, &x.maker_ppm.to_le_bytes());
            put(&mut b, 32, &x.auction_ppm.to_le_bytes());
            put(&mut b, 36, &x.msg_fee_improve.to_le_bytes());
            put(&mut b, 40, &x.msg_fee_cross.to_le_bytes());
            put(&mut b, 48, &x.base_free.to_le_bytes());
            put(&mut b, 56, &x.quote_free.to_le_bytes());
            a.extend(b);
        }
        let mut s = Vec::new();
        for x in &self.sessions {
            let mut b = vec![0u8; 32];
            put(&mut b, 0, &x.id.to_le_bytes());
            put(&mut b, 4, &x.acct.to_le_bytes());
            put(&mut b, 8, &x.book.to_le_bytes());
            put(&mut b, 16, &x.k_seq);
            s.extend(b);
        }
        (c, a, s)
    }
}

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    if let Some(d) = b.get_mut(at..at.saturating_add(v.len())) {
        d.copy_from_slice(v);
    }
}

/// The client behind [`ReplayEngine`]; `P` holds the payloads, as for [`crate::RustReplay`].
pub struct VxReplay<P> {
    client: Client,
    payloads: P,
    n: usize,
    /// Records written per lane, steps written, outputs read per lane and TX packets read.
    in_head: Vec<u64>,
    step_head: u64,
    out_tail: Vec<u64>,
    tx_tail: u64,
    lane_out: Vec<Vec<u8>>,
    tx_out: Vec<u8>,
}

/// Shared-region offsets (pbv.h): control lines first, then the rings.
struct Map {
    n: usize,
}

impl Map {
    fn in_head(&self, l: usize) -> usize {
        1 + 4 * l
    }
    fn in_tail(&self, l: usize) -> usize {
        2 + 4 * l
    }
    fn out_head(&self, l: usize) -> usize {
        3 + 4 * l
    }
    fn out_tail(&self, l: usize) -> usize {
        4 + 4 * l
    }
    fn step(&self, k: usize) -> usize {
        1 + 4 * self.n + k
    }
    fn in_base(&self) -> usize {
        (1 + 4 * (self.n + 1)) * 128
    }
    fn out_base(&self) -> usize {
        self.in_base() + self.n * SLOTS as usize * IN_BYTES
    }
    fn step_base(&self) -> usize {
        self.out_base() + self.n * SLOTS as usize * OUT_BYTES
    }
    fn tx_base(&self) -> usize {
        self.step_base() + SLOTS as usize * STEP_BYTES
    }
}

fn word(m: &[Line], line: usize, w: usize) -> u64 {
    m.get(line)
        .and_then(|l| l.0.get(w))
        .map_or(0, |a| a.load(Ordering::Acquire))
}

fn set(m: &[Line], line: usize, w: usize, v: u64) {
    if let Some(a) = m.get(line).and_then(|l| l.0.get(w)) {
        a.store(v, Ordering::Release);
    }
}

/// Writes `b` (a multiple of 8 bytes) at byte offset `at` (8-aligned).
fn write(m: &[Line], at: usize, b: &[u8]) {
    for (i, c) in b.as_chunks::<8>().0.iter().enumerate() {
        let w = at / 8 + i;
        let v = u64::from_le_bytes(*c);
        if let Some(a) = m.get(w / 16).and_then(|l| l.0.get(w % 16)) {
            a.store(v, Ordering::Relaxed);
        }
    }
}

/// Reads `len` bytes at byte offset `at` (8-aligned).
fn read(m: &[Line], at: usize, len: usize, out: &mut Vec<u8>) {
    let start = out.len();
    for i in 0..len.div_ceil(8) {
        let w = at / 8 + i;
        let v = m
            .get(w / 16)
            .and_then(|l| l.0.get(w % 16))
            .map_or(0, |a| a.load(Ordering::Relaxed));
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.truncate(start.saturating_add(len));
}

/// A slot that holds a `MID` record (flags at byte 2).
fn is_mid(b: &[u8]) -> bool {
    b.get(2).is_some_and(|f| f & PacketFlags::MID != 0)
}

fn byte(m: &[Line], at: usize) -> usize {
    let mut b = Vec::new();
    read(m, at & !7, 8, &mut b);
    b.get(at % 8).copied().map_or(0, usize::from)
}

fn err(m: &[Line], what: &str, code: u64, at: u64) -> ReplayError {
    let why = usize::try_from(code)
        .ok()
        .and_then(|c| ERRS.get(c))
        .unwrap_or(&"unknown");
    // A diverged client stays diverged: stop its threads now.
    set(m, 0, 0, 1);
    ReplayError(format!("vx client: {what}: diverged ({why}) at {at}"))
}

impl<P: Payloads> VxReplay<P> {
    /// Loads the library at `lib` and starts the client in `cfg`'s state.
    pub fn new(lib: &Path, cfg: &VxConfig, payloads: P) -> Result<Self, ReplayError> {
        let (c, a, s) = cfg.tables();
        let client = Client::start(lib, &c, &a, &s).map_err(ReplayError)?;
        let n = usize::from(cfg.n_lanes);
        Ok(Self {
            client,
            payloads,
            n,
            in_head: vec![0; n],
            step_head: 0,
            out_tail: vec![0; n],
            tx_tail: 0,
            lane_out: vec![Vec::new(); n],
            tx_out: Vec::new(),
        })
    }

    /// The payload store, to fill before a block.
    pub fn payloads_mut(&mut self) -> &mut P {
        &mut self.payloads
    }

    /// The last block's response bytes of each lane (`encode_resp`'s form).
    pub fn lane_bytes(&self) -> &[Vec<u8>] {
        &self.lane_out
    }

    /// The last block's fill TX bytes (`encode_tx`'s form).
    pub fn tx_bytes(&self) -> &[u8] {
        &self.tx_out
    }

    /// One input slot: the record, its routes and its payload.
    fn slot(
        &self,
        at: usize,
        p: &PacketRecord,
        routes: &[RouteRecord],
    ) -> Result<Vec<u8>, ReplayError> {
        let mut b = vec![0u8; IN_BYTES];
        let advance = p.flags & PacketFlags::ADVANCE != 0;
        // A `SHED` record replays from the record alone (05 §18 Q17): no payload.
        let pay: &[u8] = if advance || p.flags & PacketFlags::SHED != 0 {
            &[]
        } else {
            self.payloads
                .get(p)
                .ok_or_else(|| ReplayError(format!("no payload for record {at}")))?
        };
        let rs: Vec<_> = routes
            .iter()
            .filter(|x| {
                let lo = p.first_lane_seq.0;
                !advance
                    && x.lane == p.lane
                    && lo <= x.lane_seq.0
                    && x.lane_seq.0 < lo.saturating_add(u64::from(p.count))
            })
            .collect();
        if rs.len() > MAX_ROUTES || pay.len() > IN_BYTES - IN_PAYLOAD {
            return Err(ReplayError(format!("record {at} does not fit a pbv slot")));
        }
        put(&mut b, 0, &[p.lane.0, p.count, p.flags, rs.len() as u8]);
        put(&mut b, 4, &p.session.0.to_le_bytes());
        put(&mut b, 8, &p.pkt_seq.to_le_bytes());
        put(&mut b, 12, &(pay.len() as u32).to_le_bytes());
        put(&mut b, 16, &p.rx_ts.0.to_le_bytes());
        put(&mut b, 24, &p.pkt_hash.0.to_le_bytes());
        put(&mut b, 32, &p.first_lane_seq.0.to_le_bytes());
        put(&mut b, 40, &p.fills_applied.0.to_le_bytes());
        put(&mut b, 48, &(at as u64).to_le_bytes());
        put(&mut b, 56, &p.snap_lag.to_le_bytes());
        for (i, x) in rs.iter().enumerate() {
            put(&mut b, IN_ROUTES + 16 * i, &x.lane_seq.0.to_le_bytes());
            put(&mut b, IN_ROUTES + 16 * i + 8, &[u8::from(x.cross)]);
        }
        put(&mut b, IN_PAYLOAD, pay);
        Ok(b)
    }

    /// Moves every output the client has written into this block's bytes.
    fn drain(&mut self, map: &Map) {
        let m = self.client.mem();
        for (l, (tail, out)) in self.out_tail.iter_mut().zip(&mut self.lane_out).enumerate() {
            let head = word(m, map.out_head(l), 0);
            while *tail < head {
                let at =
                    map.out_base() + (l * SLOTS as usize + (*tail % SLOTS) as usize) * OUT_BYTES;
                let k = byte(m, at + 12);
                read(m, at, 13 + 16 * k, out);
                *tail += 1;
            }
            set(m, map.out_tail(l), 0, *tail);
        }
        let head = word(m, map.step(2), 0);
        while self.tx_tail < head {
            let at = map.tx_base() + (self.tx_tail % SLOTS) as usize * TX_BYTES;
            let k = byte(m, at + 21);
            read(m, at, 23 + 16 * k, &mut self.tx_out);
            self.tx_tail += 1;
        }
        set(m, map.step(3), 0, self.tx_tail);
    }
}

impl<P: Payloads, const N: usize> ReplayEngine<N> for VxReplay<P> {
    fn load_snapshot(&mut self, _: &StateSnapshot) -> Result<(), ReplayError> {
        Err(ReplayError("no canonical state encoding yet".into()))
    }

    #[allow(clippy::indexing_slicing)]
    fn replay_block(&mut self, blk: &BlockInputs<N>) -> Result<BlockOutputs, ReplayError> {
        if self.n != N {
            return Err(ReplayError(format!(
                "block is {N} lanes wide, the client {}",
                self.n
            )));
        }
        let map = Map { n: N };
        let routes: Vec<RouteRecord> = blk
            .lanes
            .iter()
            .filter_map(|r| match r {
                LaneRec::Route(x) => Some(*x),
                _ => None,
            })
            .collect();
        // Each lane's slots, in O-order. A route joins the last packet whose range holds it.
        let mut lanes: Vec<Vec<Vec<u8>>> = vec![Vec::new(); N];
        let pkts: Vec<(usize, PacketRecord)> = blk
            .lanes
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match r {
                LaneRec::Pkt(p) => Some(Ok((i, *p))),
                LaneRec::Take(_) => Some(Err(ReplayError("AcctTake replay".into()))),
                LaneRec::Route(_) => None,
            })
            .collect::<Result<_, _>>()?;
        // The last packet whose range holds each (lane, LaneSeq), in one pass; then each
        // packet's routes in one more.
        let mut owner = std::collections::BTreeMap::new();
        for (j, (_, p)) in pkts.iter().enumerate() {
            if p.flags & PacketFlags::ADVANCE == 0 {
                let lo = p.first_lane_seq.0;
                for q in lo..lo.saturating_add(u64::from(p.count)) {
                    owner.insert((p.lane.0, q), j);
                }
            }
        }
        let mut owned: Vec<Vec<RouteRecord>> = vec![Vec::new(); pkts.len()];
        for x in &routes {
            if let Some(o) = owner
                .get(&(x.lane.0, x.lane_seq.0))
                .and_then(|&j| owned.get_mut(j))
            {
                o.push(*x);
            }
        }
        for ((i, p), own) in pkts.iter().zip(&owned) {
            let l = usize::from(p.lane.0);
            if l >= N {
                return Err(ReplayError(format!("record {i}: lane {l}")));
            }
            lanes[l].push(self.slot(*i, p, own)?);
        }
        let mut steps = Vec::new();
        for s in &blk.steps {
            if !s.payload.is_empty() {
                return Err(ReplayError("vx client: step payloads are not in v1".into()));
            }
            let mut b = vec![0u8; STEP_BYTES];
            put(&mut b, 0, &s.rec.step.0.to_le_bytes());
            let src = s.rec.src_lane_seq.0 != 0;
            let cross = s.rec.flags & vyrn_types::StepFlags::CROSS != 0;
            put(
                &mut b,
                8,
                &[
                    s.rec.kind.code(),
                    u8::from(src),
                    s.rec.src_lane.0,
                    u8::from(cross),
                ],
            );
            put(&mut b, 16, &s.rec.src_lane_seq.0.to_le_bytes());
            for (l, c) in s.rec.cut.iter().enumerate() {
                put(&mut b, 32 + 8 * l, &c.0.to_le_bytes());
            }
            steps.push(b);
        }
        let last = blk.header.last_step.0;
        self.lane_out.iter_mut().for_each(Vec::clear);
        self.tx_out.clear();
        // Tell each lane how far this block's records go, so the BBO never reads a ring the
        // shell is still filling as exhausted input.
        for (l, recs) in lanes.iter().enumerate() {
            let fed = self.in_head[l] + recs.len() as u64;
            set(self.client.mem(), map.in_head(l), 1, fed);
        }
        let mut next = vec![0usize; N];
        let mut next_step = 0usize;
        loop {
            let m = self.client.mem();
            // Feed what fits, a packet and its `MID` records at once: the lane takes a call's
            // records together, so in_head never stops between them.
            for l in 0..N {
                let tail = word(m, map.in_tail(l), 0);
                while next[l] < lanes[l].len() {
                    let mut k = 1;
                    while lanes[l].get(next[l] + k).is_some_and(|b| is_mid(b)) {
                        k += 1;
                    }
                    if self.in_head[l] + k as u64 - tail > SLOTS {
                        break;
                    }
                    for b in &lanes[l][next[l]..next[l] + k] {
                        let at = map.in_base()
                            + (l * SLOTS as usize + (self.in_head[l] % SLOTS) as usize) * IN_BYTES;
                        write(m, at, b);
                        self.in_head[l] += 1;
                    }
                    next[l] += k;
                }
                set(m, map.in_head(l), 0, self.in_head[l]);
            }
            let tail = word(m, map.step(1), 0);
            while next_step < steps.len() && self.step_head - tail < SLOTS {
                let at = map.step_base() + (self.step_head % SLOTS) as usize * STEP_BYTES;
                write(m, at, &steps[next_step]);
                next_step += 1;
                self.step_head += 1;
            }
            set(m, map.step(0), 0, self.step_head);
            // Errors.
            for l in 0..N {
                let e = word(m, map.in_tail(l), 3);
                if e != 0 {
                    return Err(err(m, &format!("lane {l}"), e, word(m, map.in_tail(l), 4)));
                }
            }
            let e = word(m, map.step(1), 2);
            if e != 0 {
                return Err(err(m, "bbo", e, word(m, map.step(1), 3)));
            }
            // Done: the last step ran, then every lane is used up or waits on a later step.
            let fed = next_step == steps.len() && (0..N).all(|l| next[l] == lanes[l].len());
            let stepped = steps.is_empty() || word(m, map.step(1), 1) >= last;
            let quiet = stepped
                && (0..N).all(|l| {
                    let t = word(m, map.in_tail(l), 0);
                    t == self.in_head[l]
                        || (word(m, map.in_tail(l), 1) == self.in_head[l]
                            && word(m, map.in_tail(l), 2) > last)
                });
            self.drain(&map);
            if fed && quiet {
                break;
            }
            std::thread::yield_now();
        }
        Ok(BlockOutputs {
            output_hash: crate::output_hash(&self.lane_out, &self.tx_out),
        })
    }

    fn write_state(&self, _: &mut CanonicalStateWriter) -> Result<(), ReplayError> {
        Err(ReplayError("no canonical state encoding yet".into()))
    }
}
