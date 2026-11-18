//! `RustReplay`: [`ReplayEngine`] over `vyrn-engine` in replay mode (11 §5.3, 07 §7.1).
//!
//! # Contract
//!
//! **Input.** One [`BlockInputs`] per block, in height order, as [`crate::OrderCore::take_ready`]
//! yields them, on one engine that started from the tenure's initial state. `blk.lanes` holds
//! `PacketRecord`s (Advance records included) and `RouteRecord`s; `blk.steps` the merged steps.
//! The payload of every packet comes from `P` ([`crate::DataJoin`] in the replica), which the
//! shell fills before the call and releases after it ([`RustReplay::payloads_mut`]).
//!
//! **Order.** The packet records go to `Engine::replay_wire` in the order the block holds them
//! (each lane in O-order, lanes interleaved), the route records in any order, and the steps in
//! StepId order. The engine merges them by 07 §7.1 `REP_MERGE` and carries the lane records a
//! block does not settle into the next call (`Engine::carried`).
//!
//! **Output.** Every order-stream record, lane response and fill TX packet the engine produces
//! goes to the sink `S`, and responses are checked against `R` (`vyrn_engine::NoResponses` for
//! none; [`RustReplay::finish`] checks the log is used up after the last block).
//! [`BlockOutputs::output_hash`] is
//!
//! ```text
//! BLAKE3("vyrn v1 out" ‖ H(lane 0) ‖ … ‖ H(lane N−1) ‖ H(tx))
//! H(lane l) = BLAKE3(each response of lane l, in order: session u32 ‖ resp_seq u32 ‖
//!             echo_pkt u32 ‖ n u8 ‖ n × record[16])
//! H(tx)     = BLAKE3(each fill TX packet, in step order: step u64 ‖ session u32 ‖ resp_seq u32 ‖
//!             pkt_seq u32 ‖ lane u8 ‖ n_rec u8 ‖ role u8 ‖ n_rec × record[16])
//! ```
//!
//! all little-endian, over the outputs of this call only. Responses are hashed per lane because
//! `REP_MERGE` fixes each lane's order but not the order across lanes, so two clients agree on
//! these bytes and on nothing finer. The response `gate` is physical (when a frame is sent) and
//! is not hashed. 11 §5.3 names the output hash but not its bytes, so this encoding is a spec
//! gap [Guessing: ours, PR body].
//!
//! **Reject reasons** ([`ReplayError`]; any of them halts this replica's attestations):
//! - the block's step records are not `N` lanes wide where the engine has a different count;
//! - the block holds an `AcctTake` (pooled lanes, 01 §14.17): not replayed yet;
//! - `Engine::replay_wire` diverged (`WireDiverged { at, why }`, in the message);
//! - `load_snapshot` and `write_state`: the engine has no canonical state encoding yet.

use vyrn_bbo::{Record, TxEntry};
use vyrn_cut::Visibility;
use vyrn_engine::{Engine, Payloads, Rec, Responses, Sink, WireStep};
use vyrn_lane::RespPkt;
use vyrn_log::LaneRec;
use vyrn_types::{AcctTake, Hash, LaneId, PacketRecord, RouteRecord};

use crate::ports::{
    BlockInputs, BlockOutputs, CanonicalStateWriter, ReplayEngine, ReplayError, StateSnapshot,
};

/// The domain tag of [`BlockOutputs::output_hash`].
pub const OUTPUT_DOMAIN: &[u8] = b"vyrn v1 out";

/// `vyrn-engine` in replay mode behind [`ReplayEngine`].
pub struct RustReplay<'a, V: Visibility, const NA: usize, P, R, S> {
    engine: Engine<'a, V, NA>,
    payloads: P,
    log: R,
    sink: S,
    /// Per-block scratch, reused: packet and route records, per-lane and TX output bytes.
    pkts: Vec<PacketRecord>,
    routes: Vec<RouteRecord>,
    lane_out: Vec<Vec<u8>>,
    tx_out: Vec<u8>,
}

impl<'a, V: Visibility, const NA: usize, P: Payloads, R: Responses, S: Sink>
    RustReplay<'a, V, NA, P, R, S>
{
    /// Replays on `engine`, which must be in the tenure's initial state.
    pub fn new(engine: Engine<'a, V, NA>, payloads: P, log: R, sink: S) -> Self {
        let n = engine.cut().len();
        Self {
            engine,
            payloads,
            log,
            sink,
            pkts: Vec::new(),
            routes: Vec::new(),
            lane_out: vec![Vec::new(); n],
            tx_out: Vec::new(),
        }
    }

    /// The payload store, to fill before a block and release after it.
    pub fn payloads_mut(&mut self) -> &mut P {
        &mut self.payloads
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Ends replay and hands back the sink.
    pub fn into_sink(self) -> S {
        self.sink
    }

    pub fn engine(&self) -> &Engine<'a, V, NA> {
        &self.engine
    }

    /// After the last block: the response log holds nothing replay did not produce.
    pub fn finish(&self) -> Result<(), ReplayError> {
        if self.log.finished() {
            Ok(())
        } else {
            Err(ReplayError("response log not used up".into()))
        }
    }
}

impl<V: Visibility, const NA: usize, P: Payloads, R: Responses, S: Sink, const N: usize>
    ReplayEngine<N> for RustReplay<'_, V, NA, P, R, S>
{
    fn load_snapshot(&mut self, _: &StateSnapshot) -> Result<(), ReplayError> {
        Err(ReplayError("no canonical state encoding yet".into()))
    }

    fn replay_block(&mut self, blk: &BlockInputs<N>) -> Result<BlockOutputs, ReplayError> {
        if self.lane_out.len() != N {
            return Err(ReplayError(format!(
                "block is {N} lanes wide, the engine {}",
                self.lane_out.len()
            )));
        }
        self.pkts.clear();
        self.routes.clear();
        for r in &blk.lanes {
            match r {
                LaneRec::Pkt(p) => self.pkts.push(*p),
                LaneRec::Route(x) => self.routes.push(*x),
                LaneRec::Take(_) => return Err(ReplayError("AcctTake replay".into())),
            }
        }
        let steps: Vec<WireStep<'_>> = blk
            .steps
            .iter()
            .map(|m| WireStep::of(&m.rec, &m.payload))
            .collect();
        self.lane_out.iter_mut().for_each(Vec::clear);
        self.tx_out.clear();
        let mut tee = Tee {
            inner: &mut self.sink,
            lanes: &mut self.lane_out,
            tx: &mut self.tx_out,
        };
        self.engine
            .replay_wire(
                &self.pkts,
                &self.routes,
                &steps,
                &self.payloads,
                &mut self.log,
                &mut tee,
            )
            .map_err(|d| {
                ReplayError(format!(
                    "height {}: diverged at {:?}: {:?}",
                    blk.header.height.0, d.at, d.why
                ))
            })?;
        Ok(BlockOutputs {
            output_hash: output_hash(&self.lane_out, &self.tx_out),
        })
    }

    fn write_state(&self, _: &mut CanonicalStateWriter) -> Result<(), ReplayError> {
        Err(ReplayError("no canonical state encoding yet".into()))
    }
}

/// [`BlockOutputs::output_hash`] from the per-lane and TX bytes (module docs).
pub fn output_hash(lanes: &[Vec<u8>], tx: &[u8]) -> Hash {
    let mut b = OUTPUT_DOMAIN.to_vec();
    for l in lanes {
        b.extend_from_slice(&vyrn_crypto::hash::hash(l).0);
    }
    b.extend_from_slice(&vyrn_crypto::hash::hash(tx).0);
    vyrn_crypto::hash::hash(&b)
}

/// The bytes one lane response adds to `H(lane l)`.
pub fn encode_resp(out: &mut Vec<u8>, p: &RespPkt) {
    let recs = p.records();
    out.extend_from_slice(&p.session.0.to_le_bytes());
    out.extend_from_slice(&p.resp_seq.to_le_bytes());
    out.extend_from_slice(&p.echo_pkt.to_le_bytes());
    out.push(u8::try_from(recs.len()).unwrap_or(u8::MAX));
    recs.iter().for_each(|r| out.extend_from_slice(&r.encode()));
}

/// The bytes one fill TX packet adds to `H(tx)`.
pub fn encode_tx(out: &mut Vec<u8>, h: &TxEntry, recs: &[Record]) {
    out.extend_from_slice(&h.step.0.to_le_bytes());
    out.extend_from_slice(&h.session.0.to_le_bytes());
    out.extend_from_slice(&h.resp_seq.to_le_bytes());
    out.extend_from_slice(&h.pkt_seq.to_le_bytes());
    out.extend_from_slice(&[h.lane.0, h.n_rec, h.role]);
    recs.iter().for_each(|r| out.extend_from_slice(&r.encode()));
}

/// Forwards every output to the caller's sink and keeps the bytes the output hash covers.
struct Tee<'s, S> {
    inner: &'s mut S,
    lanes: &'s mut [Vec<u8>],
    tx: &'s mut Vec<u8>,
}

impl<S: Sink> Sink for Tee<'_, S> {
    fn record(&mut self, r: &Rec<'_>) {
        self.inner.record(r);
    }
    fn lane_resp(&mut self, lane: LaneId, p: &RespPkt) {
        // `replay_wire` rejects a record of a lane the engine lacks, so the lane exists.
        if let Some(b) = self.lanes.get_mut(usize::from(lane.0)) {
            encode_resp(b, p);
        }
        self.inner.lane_resp(lane, p);
    }
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) {
        encode_tx(self.tx, h, recs);
        self.inner.tx(h, recs);
    }
    fn take(&mut self, t: &AcctTake) {
        self.inner.take(t);
    }
}
