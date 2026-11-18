//! Vx client golden replays of pinned `vyrn-sim` seeds (`tests/seeds.toml`): the seed's live
//! order stream, framed as 07 and decoded by `OrderCore`, replayed by `RustReplay` and by the Vx
//! client (`VxReplay`, 11 §5.3). Both must give the same output hash.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use vyrn_engine::OwnedRec;
use vyrn_log::{Ident, LaneBase, Layout, SeqWriter, TenureStart};
use vyrn_replica::{
    BlockInputs, DataJoin, EpochView, OrderCore, ReplayEngine, RustReplay, VxAccount, VxConfig,
    VxReplay, VxSession, full_hash,
};
use vyrn_sim::cluster::{self, BOOK, Out, Schedule, Store, TICK_MAX};
use vyrn_types::{
    BookId, Epoch, Hash, Height, LaneSeq, Nanos, PacketFlags, PubKey, StepFlags, StepId, StepKind,
};

const SEED: [u8; 32] = [0x44; 32];

#[derive(Clone)]
struct View(PubKey);

impl EpochView for View {
    fn epoch(&self) -> Epoch {
        Epoch(0)
    }
    fn book(&self) -> BookId {
        BOOK
    }
    fn seq_key(&self, sender: u8) -> Option<PubKey> {
        (sender == 0).then_some(self.0)
    }
    fn fenced(&self, _: Height) -> bool {
        false
    }
}

/// The live order stream as one 07 block (the sim box runs no Control or Uncross steps).
fn blocks<const N: usize>(out: &Out, store: &Store) -> Vec<BlockInputs<N>> {
    let layout = Layout::new(u8::try_from(N).unwrap(), 1, 0).unwrap();
    let ident = Ident {
        book: BOOK,
        epoch: Epoch(0),
        tenure: 0,
        sender: 0,
    };
    let tenure = TenureStart {
        epoch: Epoch(0),
        tenure: 0,
        sender: 0,
        first_step: StepId(1),
        first_height: Height(0),
        prev_header_hash: Hash([0; 32]),
        lanes: vec![
            LaneBase {
                next_lane_seq: LaneSeq(1),
                rx_ts: Nanos(0),
                fills_applied: StepId(0),
            };
            N
        ],
        prev_cut: vec![LaneSeq(0); N],
    };
    let mut w = SeqWriter::new(layout, ident, tenure, SEED, 9000).unwrap();
    let mut frames = Vec::new();
    let mut cut = vec![LaneSeq(0); N];
    for r in &out.recs {
        match r {
            OwnedRec::Packet(p) => {
                let full = (p.flags & PacketFlags::ADVANCE == 0).then(|| {
                    let k = (p.lane.0, p.session.0, p.pkt_seq, p.rx_ts.0);
                    let (_, b) = store.iter().find(|(x, _)| **x == k).unwrap();
                    full_hash(b)
                });
                frames.extend(w.packet(*p, full).unwrap());
            }
            OwnedRec::Route(t) => frames.extend(w.route(*t).unwrap()),
            OwnedRec::Take(t) => frames.extend(w.take(*t).unwrap()),
            OwnedRec::Step(e, d) => {
                for x in &d[..usize::from(e.n_delta)] {
                    cut[usize::from(x.lane.0)] = x.seq;
                }
                let kind = StepKind::from_code(e.kind).unwrap();
                assert!(
                    !matches!(kind, StepKind::Control | StepKind::Uncross | StepKind::Seal),
                    "the sim box runs no control role"
                );
                let mut payload = Vec::new();
                if kind == StepKind::Rescan {
                    payload.extend_from_slice(&e.band_lo.0.to_le_bytes());
                    payload.extend_from_slice(&e.band_hi.0.to_le_bytes());
                }
                let src = (e.src_lane_seq.0 != 0).then_some((e.src_lane, e.src_lane_seq));
                let flags = if src.is_some() && e.flags & vyrn_bbo::STEP_CROSS != 0 {
                    StepFlags::CROSS
                } else {
                    0
                };
                frames.extend(
                    w.step(e.step, kind, src, flags, payload, &cut, e.lowver)
                        .unwrap(),
                );
            }
        }
    }
    frames.extend(w.close_block().unwrap().0);
    let key = vyrn_crypto::ed25519::public_key(&SEED);
    let mut core = OrderCore::<N, _>::new(layout, View(key)).unwrap();
    for f in frames {
        core.on_frame(&f, 0).unwrap();
    }
    std::iter::from_fn(|| core.take_ready()).collect()
}

fn data(store: &Store) -> DataJoin {
    let mut d = DataJoin::default();
    for ((_, s, q, _), b) in store.iter() {
        d.put(vyrn_types::SessionId(*s), *q, b.clone());
    }
    d
}

/// The sim box (`cluster::engine`) as the Vx client's tables.
fn vx_config(cfg: &cluster::Config) -> VxConfig {
    use vyrn_risk::consts as k;
    let mut c = VxConfig {
        n_lanes: u8::try_from(cfg.lanes).unwrap(),
        book: BOOK.0,
        epoch: 0,
        tick_min: 1,
        tick_max: TICK_MAX,
        tick_size: 1,
        band_bps: 10_000,
        slot_cap: 4096,
        seg_cap: 4096,
        pool: 0,
        ..VxConfig::default()
    };
    for l in 0..cfg.lanes {
        for a in 1..=cfg.sessions {
            c.accounts.push(VxAccount {
                slot: a,
                lane: u8::try_from(l).unwrap(),
                state: 0,
                max_open: 4000,
                max_qty: u32::MAX,
                max_notional: k::RSK_DEFAULT_MAX_NOTIONAL,
                taker_ppm: k::RSK_DEFAULT_TAKER_PPM,
                maker_ppm: k::RSK_DEFAULT_MAKER_PPM,
                auction_ppm: k::RSK_DEFAULT_AUCTION_PPM,
                msg_fee_improve: k::RSK_DEFAULT_MSG_FEE_IMPROVE,
                msg_fee_cross: k::RSK_DEFAULT_MSG_FEE_CROSS,
                base_free: 1 << 40,
                quote_free: 1 << 60,
                pool_ix: None,
            });
            c.sessions.push(VxSession {
                id: cluster::sid(l, a).0,
                acct: a,
                book: BOOK.0,
                k_seq: cluster::kseq(l, a),
                pooled: None,
            });
        }
    }
    c
}

/// `target/vx/libvyrn_vx_client` (or `VYRN_VX_CLIENT_LIB`), or `None` unless `VYRN_REQUIRE_VX`.
fn vx_lib() -> Option<std::path::PathBuf> {
    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    let lib = std::env::var_os("VYRN_VX_CLIENT_LIB").map_or_else(
        || {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../target/vx/libvyrn_vx_client.{ext}"))
        },
        std::path::PathBuf::from,
    );
    if lib.exists() {
        return Some(lib);
    }
    assert!(
        std::env::var_os("VYRN_REQUIRE_VX").is_none(),
        "{} is missing",
        lib.display()
    );
    eprintln!("skipped: {} is missing; run vx/build.sh", lib.display());
    None
}

/// Seed 6f with faults `drop 31` (tests/seeds.toml, #199) as a 07 log: replay's `lowver` is an
/// input there. With the logged LOWVER mask ignored, the band reset publishes other bounds and
/// snapshot versions than live, and a later packet names a version replay never published
/// (`NoSnapshot`). The log has in-packet dependencies (gap item 5), so until they are in the Vx
/// client's subset it must either match `RustReplay` or stop with UNSUPPORTED, never differ.
#[test]
fn the_vx_client_replays_sim_seed_6f() {
    const N: usize = 3;
    let (report, out, store) = cluster::run_log(0x6f, &Schedule::parse("drop 31").unwrap());
    assert!(report.violation.is_none(), "{:?}", report.violation);
    assert_eq!(report.config.lanes, N);
    let blocks = blocks::<N>(&out, &store);
    assert!(
        blocks
            .iter()
            .any(|b| b.steps.iter().any(|m| m.rec.lowver != 0)),
        "the log has LOWVER steps"
    );
    let (bbo, mut sh) = cluster::new_box(N);
    let mut rust = RustReplay::new(
        cluster::engine(bbo, &mut sh, &report.config),
        data(&store),
        vyrn_engine::NoResponses,
        Out::default(),
    );
    let want: Vec<Hash> = blocks
        .iter()
        .map(|b| rust.replay_block(b).unwrap().output_hash)
        .collect();
    let Some(lib) = vx_lib() else { return };
    let mut vx = VxReplay::new(&lib, &vx_config(&report.config), data(&store)).unwrap();
    let got = blocks
        .iter()
        .map(|b| vx.replay_block(b).map(|o| o.output_hash))
        .collect::<Result<Vec<_>, _>>();
    match got {
        Ok(got) => assert_eq!(got, want),
        Err(e) => assert!(format!("{e:?}").contains("(unsupported)"), "{e:?}"),
    }
}
