//! Deterministic whole-cluster simulator, oracle binding, invariant checkers. Test-only
//! (spec/11-build.md §6.4, invariants of 01 §7 and 02).
//!
//! # Contract
//!
//! **Run.** [`cluster::run`] takes a 64-bit seed and a fault [`cluster::Schedule`] and returns a
//! [`cluster::Report`]. One thread, virtual time in nanoseconds, no wall clock, no `HashMap`, no
//! float, no OS state: the same `(seed, schedule)` gives the same report, byte for byte, on every
//! host (`INV-DET` of the simulator itself, 11 §6.4). [`cluster::Report::trace`] is a BLAKE3
//! hash over every scheduled event and every engine output in order, so two runs agree iff their
//! traces agree.
//!
//! **Randomness.** Each component draws from its own ChaCha8 stream seeded with
//! `BLAKE3(seed_le ‖ component name)` ([`rng::stream`]), so adding a component does not shift
//! another's draws. Components: `config`, `workload`, `net`, `faults`, `sched` (event ties).
//!
//! **Swarm configuration** ([`cluster::Config::from_seed`]). Each seed picks the lane count
//! (1–8), sessions per lane (1–7), the number of replicas (2–4), the workload length and
//! intensity, and which fault classes the generated schedule may hold.
//!
//! **Cluster.** Every box runs the real crates, not models of them:
//!
//! ```text
//!  clients ×k ──► sim network (latency, SF-01 drop / dup / delay) ──► vyrn-seq box
//!     │             vyrn-engine live: lanes (vyrn-lane) → cut → BBO (vyrn-bbo) → order stream
//!     ▲                    │ responses (lane and fill TX)          │ order stream + payloads
//!     └── Rx verdicts ◄────┘                                       ▼
//!                                            replicas ×n: vyrn-engine replay on a fresh box
//! ```
//!
//! - A client sends packets of 1–3 orders on its session (window 4), keeps every packet until
//!   the lane accepts it, and resends the oldest unaccepted ones on a timer (SF-01, `Shed`).
//! - Each lane processes arrivals in order at `max(arrival, lane free)`; its deadline clock is
//!   the virtual time of processing, so a lane stall (SF-11) sheds late packets (SF-27). After
//!   each packet the BBO core runs to quiescence at `max(now, bbo free)`; a BBO stall (SF-12)
//!   makes forwarded ops late, which yields `Shed` steps.
//! - Every lane also takes an idle poll every [`cluster::POLL_NS`].
//! - Replicas receive the order stream and the payload store and replay them with
//!   `vyrn_engine::Engine::replay`. SF-24 (only when the schedule names it) flips one field of
//!   one record in one replica's copy, which `INV-DET` must catch.
//!
//! **Checks** ([`check`]). After every event, on the live run: `INV-CUT-MONO` (each step's cut
//! is pointwise ≥ the previous step's), step fill cap (`n_fills ≤ STEP_FILL_CAP`),
//! `INV-UNCROSSED` (BBO snapshot bid < ask or one side empty), shed logged (every `Shed`
//! verdict has a `SHED` packet record), session order (in-stream `resp_seq` strictly increasing
//! per session). At the end: liveness (every client's packets accepted within
//! [`cluster::HEAL_NS`] after the last fault) and `INV-DET` (every replica's replayed order
//! stream, lane responses and fill TX packets equal the live run's, byte for byte, with the
//! physical publication ids `pub_a`/`pub_b` zeroed as `vyrn-engine` specifies). The first
//! broken check stops the run: [`check::Violation`] names it, the event index and a detail.
//!
//! **Faults** ([`cluster::Fault`]). A schedule is data: a list of `(id, kind)` lines with a
//! text form ([`cluster::Schedule::parse`], [`cluster::Schedule::render`]), so a failing run is
//! reproduced by `vyrn-sim run --seed <hex> --faults '<schedule>'` on any implementation that
//! reads the same format. `vyrn-sim shrink` removes faults one at a time while the failure
//! persists (delta debugging over the schedule, 11 §6.4) and prints the smallest schedule.
//!
//! **Not modelled yet** (PR follow-ups): `vyrn-log` framing between the sequencer and the
//! replicas, `vyrn-data`, Simplex consensus on `commonware-runtime::deterministic`, the standby
//! sequencer and failover, epochs, the `Sim` visibility backend's delays (SF-13; `Bbo::replay_step` is on
//! main, wiring it is a follow-up), pooled lanes, the Vx client, and the checks that need those parts
//! (`INV-FRAME-FIRST`, `INV-QUORUM`, `INV-FENCE`, finality safety, conservation).
#![deny(unsafe_code)]

pub mod check;
pub mod cluster;
// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod oracle;
pub mod oracle_abi;
pub mod rng;
pub mod scenario;
