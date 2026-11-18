//! Replay of each checked block on `vyrn-engine` (`vyrn_replica::RustReplay`, 07 §6.4 after
//! item 3), and the per-block output hash it prints as `out=<hex>` on `BLOCK` lines.
//!
//! **Initial state** (reading, **config**). 08 gives no canonical state encoding yet, so a
//! replica cannot load the tenure's initial state from a snapshot (`load_snapshot` refuses).
//! `[replay]` instead names the sequencer's engine parameters and DEV sessions, the same fields
//! as `vyrn-seq`'s `[engine]` and `[[dev_session]]`, and the engine is built from them exactly
//! as `vyrn-seq` builds its live engine. A config that differs from the sequencer's diverges at
//! the first block that depends on it, which prints `REPLAY_FAULT`.
//!
//! **Responses.** The validator holds no response log, so replay checks none
//! (`vyrn_engine::NoResponses`) and its sink discards everything: `out=` is the comparison.

use serde::Deserialize;
use vyrn_bbo::{Bbo, Phase, Record, TxEntry};
use vyrn_cut::Hw;
use vyrn_engine::{Engine, NoResponses, Rec, Shared, Sink};
use vyrn_lane::{ArenaConfig, Lane, PathTable, RespPkt, SessionSpec};
use vyrn_replica::{BlockInputs, DataJoin, ReplayEngine, RustReplay};
use vyrn_risk::{AcctRisk, AcctSlot, BookSpec, SessionBuckets};
use vyrn_types::{AccountId, BookId, Epoch, Hash, LaneId, Tick};

/// Lane-local accounts per lane, as in `vyrn-seq` (`vyrn_lane::Lane`'s `NA`).
pub const NA: usize = 16;

/// `[replay]`: the sequencer's engine parameters and DEV sessions (module docs).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Section {
    pub tick_min: u32,
    pub tick_max: u32,
    pub win_center: u32,
    #[serde(default = "d_cap")]
    pub slot_cap: u32,
    #[serde(default)]
    pub session: Vec<Session>,
}

fn d_cap() -> u32 {
    1024
}

/// One of the sequencer's `[[dev_session]]`s; `k_out` is not needed to replay.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub lane: u8,
    pub slot: u16,
    pub account: u32,
    /// Hex, 16 bytes.
    pub k_seq: String,
    pub quote: u64,
    pub base: u64,
}

/// A sink that keeps nothing.
pub struct Discard;

impl Sink for Discard {
    fn record(&mut self, _: &Rec<'_>) {}
    fn lane_resp(&mut self, _: LaneId, _: &RespPkt) {}
    fn tx(&mut self, _: &TxEntry, _: &[Record]) {}
}

pub type Replay = RustReplay<'static, Hw, NA, DataJoin, NoResponses, Discard>;

fn hex16(s: &str) -> Result<[u8; 16], String> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return Err("replay.session.k_seq must be 32 hex digits".into());
    }
    let mut out = [0u8; 16];
    for (o, p) in out.iter_mut().zip(b.as_chunks::<2>().0) {
        let p = std::str::from_utf8(p.as_slice()).map_err(|e| e.to_string())?;
        *o = u8::from_str_radix(p, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// The engine in the tenure's initial state, over `join`. Built once per process on the thread
/// that replays; its `Shared` lives for the process.
pub fn open(
    s: &Section,
    n_lanes: u8,
    book: BookId,
    epoch: Epoch,
    join: DataJoin,
) -> Result<Replay, String> {
    let (tick_min, tick_max) = (Tick(s.tick_min), Tick(s.tick_max));
    let spec = BookSpec::new(1, tick_min, tick_max, 10_000).ok_or("replay tick range")?;
    let slot_cap = usize::try_from(s.slot_cap).map_err(|e| e.to_string())?;
    let bbo = Bbo::new(vyrn_bbo::Config {
        n_lanes,
        epoch,
        slot_cap,
        seg_cap: s.slot_cap,
        win_center: Tick(s.win_center),
        phase: Phase::Continuous,
        tick_min,
        tick_max,
        band_half: 0,
        band_hyst: 0,
        band_ref: Tick(s.win_center),
        pool: 0,
    });
    let arena = ArenaConfig {
        slot_cap: s.slot_cap,
        seg_cap: s.slot_cap,
        tick_min,
        tick_max,
        accounts: u32::try_from(NA).map_err(|e| e.to_string())?,
        journal: s.slot_cap,
    };
    let lanes: Vec<_> = (0..n_lanes)
        .map(|l| vyrn_lane::Config {
            lane: LaneId(l),
            n_lanes,
            epoch,
            book,
            spec,
            path: PathTable::spec(),
            fwd_deadline_ns: vyrn_lane::lane::FWD_DEADLINE_NS,
            phase: Phase::Continuous,
            out_cap: 4096,
        })
        .collect();
    let vis: &'static Hw = &Hw;
    let shared: &'static mut Shared<Hw> = Box::leak(
        Shared::new(vis, usize::from(n_lanes), arena, &bbo.initial_snapshot())
            .ok_or("replay engine shape")?,
    );
    let mut engine: Engine<'static, Hw, NA> =
        Engine::new(vis, shared, bbo, &lanes, |cfg, aw, ports| {
            let mut acct = AcctRisk::new(AccountId(1), AccountId(1));
            acct.max_open_orders = 1000;
            Lane::<Hw, NA>::new(cfg, aw, ports, acct)
        })
        .ok_or("replay engine lanes")?;
    for x in &s.session {
        let id = vyrn_wire::session_id(x.slot, LaneId(x.lane), 1).ok_or("replay.session slot")?;
        let lane = engine
            .lane_mut(usize::from(x.lane))
            .ok_or("replay.session lane")?;
        let (_, bal) = lane
            .account_mut(AcctSlot(x.account))
            .ok_or("replay.session account")?;
        bal.quote_free = u128::from(x.quote);
        bal.base_free = x.base;
        let spec = SessionSpec {
            id,
            acct: AcctSlot(x.account),
            k_seq: hex16(&x.k_seq)?,
            book,
            buckets: SessionBuckets::default(),
        };
        if !lane.open_session(&spec) {
            return Err(format!("replay.session {id:?} did not open"));
        }
    }
    Ok(RustReplay::new(engine, join, NoResponses, Discard))
}

/// Replays `b` and releases the payloads it settled. `Err` is a divergence: the engine's state is
/// then unknown and the caller stops replaying.
pub fn block<const N: usize>(rep: &mut Replay, b: &BlockInputs<N>) -> Result<Hash, String> {
    let out = rep.replay_block(b).map_err(|e| e.0)?;
    rep.release(b.header.height);
    Ok(out.output_hash)
}
