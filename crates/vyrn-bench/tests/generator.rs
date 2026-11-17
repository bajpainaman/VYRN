//! The generator's contract: determinism (B4), valid packets, the structure of the population.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use vyrn_bench::config::{Config, Mode};
use vyrn_bench::generator::{GenOptions, Generator, MsgKind, session_keys};
use vyrn_bench::stream::{StreamError, StreamHeader, parse_stream, write_stream};
use vyrn_crypto::hash::hash;
use vyrn_types::{LaneId, SessionId};
use vyrn_wire::{Msg, Request, session_lane};

fn workloads() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/workloads")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A small population with the shape of WL-REF: 2 MM lanes of 2 sessions, 4 TK and 4 RT sessions
/// over a 3-lane pool, 4 ms at 5×10⁷ msgs/s.
fn mini(mode: &str, lane: Option<u8>) -> String {
    let lane = lane.map_or(String::new(), |l| format!("lane = {l}\n"));
    format!(
        r#"
version = 1
id = "MINI"
mode = "{mode}"
book = 3
epoch16 = 9
rate_msgs_per_s = 50_000_000
{lane}
[book_model]
mid_tick = 1_000_000
spread_ticks = 2
depth_lots = 50

[burst]
rate_per_s = 2000
window_ns = 100_000
mult_ppm = 2_000_000
base_scale_ppm = 998_004

[lifetimes]
replace_ppm = 115_000
[[lifetimes.row]]
ppm = 600_000
lo_ns = 5_000
hi_ns = 100_000
[[lifetimes.row]]
ppm = 300_000
lo_ns = 100_000
hi_ns = 1_000_000
[[lifetimes.row]]
ppm = 99_950
lo_ns = 1_000_000
hi_ns = 100_000_000
[[lifetimes.row]]
ppm = 50
lo_ns = 100_000_000
hi_ns = 28_800_000_000_000

[[join_distance]]
kind = "fixed"
ppm = 400_000
d = 0
[[join_distance]]
kind = "fixed"
ppm = 200_000
d = 1
[[join_distance]]
kind = "geometric"
ppm = 300_000
base = 2
cap = 7
p_ppm = 250_000
[[join_distance]]
kind = "log_uniform"
ppm = 90_000
lo = 10
hi = 4_096
[[join_distance]]
kind = "uniform"
ppm = 10_000
base = 4_096
span = 60_000

[[cross_levels]]
ppm = 800_000
lo = 1
hi = 1
[[cross_levels]]
ppm = 120_000
lo = 2
hi = 2
[[cross_levels]]
ppm = 80_000
lo = 3
hi = 200

[cross]
ioc_ppm = 700_000
day_ppm = 250_000
fok_ppm = 50_000
through_ppm = 4_000
through_qty_pct = 120

[pool]
first_lane = 10
lanes = 3

[[phase]]
duration_ns = 2_000_000
rate_ppm = 1_000_000
[[phase]]
duration_ns = 2_000_000
rate_ppm = 500_000
cross_scale_ppm = 0

[[class]]
kind = "mm"
placement = {{ kind = "dedicated", lane_first = 0, lane_count = 2, sessions_per_lane = 2 }}
skew = {{ kind = "equal" }}
mix = {{ join = 490_000, cancel = 442_000, reduce = 20_000, improve = 15_500, cross = 2_500 }}
qty_p_ppm = 200_000
stp_cancel_newest = true
bursty = true
packets = {{ kind = "bundled", bundle_size = 10, urgent_cancel_ppm = 50_000, urgent_two_ppm = 500_000 }}

[[class]]
kind = "tk"
placement = {{ kind = "pooled", sessions = 4 }}
skew = {{ kind = "zipf", s_milli = 500 }}
mix = {{ join = 8_000, cancel = 6_500, reduce = 0, improve = 4_000, cross = 6_500 }}
qty_p_ppm = 200_000
bursty = true
packets = {{ kind = "single", two_ppm = 200_000 }}

[[class]]
kind = "rt"
placement = {{ kind = "pooled", sessions = 4 }}
skew = {{ kind = "equal" }}
mix = {{ join = 2_000, cancel = 1_500, reduce = 0, improve = 500, cross = 1_000 }}
qty_p_ppm = 500_000
packets = {{ kind = "single", two_ppm = 0 }}
"#
    )
}

fn opts(seed: u64) -> GenOptions {
    GenOptions {
        seed,
        rate_override: None,
    }
}

fn stream(cfg: &Config, seed: u64, packets: Option<u64>) -> Vec<u8> {
    let mut v = Vec::new();
    write_stream(cfg, &opts(seed), packets, &mut v).unwrap();
    v
}

#[test]
fn fixed_config_and_seed_give_a_fixed_hash() {
    let cfg = Config::parse(&mini("chain", None)).unwrap();
    let bytes = stream(&cfg, 0x5EED, None);
    // If this fails after an intended change to the generator, the stream format or the config
    // schema, regenerate it, bump the version where the format changed, and say so in the PR: it
    // is the B4 contract that the same config and seed give the same bytes on every build.
    assert_eq!(
        hex(&hash(&bytes).0),
        "262976ee000182f251b2a1db505fbbdeabdf86014177c0b4896c7bbd6fb1f28d",
        "{} bytes",
        bytes.len()
    );
}

#[derive(Deserialize)]
struct Vectors {
    version: u32,
    vector: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    config: String,
    seed: String,
    packets: u64,
    blake3: String,
}

/// `bench/workloads/vectors.toml`: what a stranger runs `vyrn-bench gen` against.
#[test]
fn committed_vectors_hold_for_every_committed_config() {
    let dir = workloads();
    let v: Vectors =
        toml::from_str(&std::fs::read_to_string(dir.join("vectors.toml")).unwrap()).unwrap();
    assert_eq!(v.version, 1);
    let mut configs: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".toml") && n != "vectors.toml")
        .collect();
    configs.sort();
    let mut covered: Vec<&str> = v.vector.iter().map(|x| x.config.as_str()).collect();
    covered.sort_unstable();
    assert_eq!(covered, configs, "every config has exactly one vector");
    for x in &v.vector {
        let text = std::fs::read_to_string(dir.join(&x.config)).unwrap();
        let cfg = Config::parse(&text).unwrap();
        let seed = u64::from_str_radix(x.seed.trim_start_matches("0x"), 16).unwrap();
        let bytes = stream(&cfg, seed, Some(x.packets));
        assert_eq!(hex(&hash(&bytes).0), x.blake3, "{}", x.config);
    }
}

#[test]
fn packets_parse_verify_and_decode() {
    for (mode, chain) in [("base", false), ("chain", true)] {
        let cfg = Config::parse(&mini(mode, None)).unwrap();
        let seed = 77;
        let mut next_seq: BTreeMap<u32, u32> = BTreeMap::new();
        let mut last_ns = 0;
        let mut n = 0;
        for p in Generator::new(&cfg, &opts(seed)).unwrap() {
            n += 1;
            assert!(p.send_ns >= last_ns && p.send_ns < cfg.duration_ns());
            last_ns = p.send_ns;
            let r = Request::parse(p.bytes()).unwrap();
            r.check_header().unwrap();
            assert!(!r.is_resend());
            let h = r.header();
            assert_eq!((h.book().0, h.epoch16.get()), (3, 9));
            let sid = h.session();
            assert_eq!(session_lane(sid), p.lane);
            let (k_seq, k_com) = session_keys(seed, sid, cfg.mode);
            assert!(r.verify_seq(&k_seq));
            match k_com {
                Some(k) => assert!(chain && r.verify_com(&k)),
                None => assert!(!chain && r.tag_com().0 == 0),
            }
            assert!(!r.verify_seq(&[0; 16]));
            for m in r.msgs() {
                m.unwrap();
            }
            // pkt_seq is gapless from 1 (04 P5).
            let e = next_seq.entry(sid.0).or_insert(1);
            assert_eq!(h.pkt_seq.get(), *e);
            *e += 1;
        }
        assert!(n > 5_000, "{n} packets");
        // 2 + 2 dedicated, and 4 + 4 pooled sessions, each with traffic.
        assert_eq!(next_seq.len(), 12);
    }
}

#[test]
fn same_inputs_same_bytes_and_any_change_differs() {
    let cfg = Config::parse(&mini("base", None)).unwrap();
    let a = stream(&cfg, 1, None);
    assert_eq!(a, stream(&cfg, 1, None));
    assert_ne!(a, stream(&cfg, 2, None));
    let (h, recs) = parse_stream(&a).unwrap();
    assert_eq!(h, StreamHeader::new(&cfg, &opts(1)));
    assert!(!recs.is_empty());
    let mut o = opts(1);
    o.rate_override = Some(25_000_000);
    let mut half = Vec::new();
    write_stream(&cfg, &o, None, &mut half).unwrap();
    assert!(half.len() < a.len() * 3 / 4 && half.len() > a.len() / 4);
    // A packet limit gives a prefix.
    let few = stream(&cfg, 1, Some(10));
    let (_, r10) = parse_stream(&few).unwrap();
    assert_eq!(r10, recs[..10]);
}

/// The lane-0 sessions' streams do not depend on who else is in the run (02 §6.2: per-session
/// PRNG streams), so WL-LANE is exactly the lane-0 part of WL-REF.
#[test]
fn lane_restriction_is_the_lane_subsequence_of_the_full_run() {
    let full = Config::parse(&mini("base", None)).unwrap();
    let lane1 = Config::parse(&mini("base", Some(1))).unwrap();
    let full_bytes = stream(&full, 9, None);
    let (_, all) = parse_stream(&full_bytes).unwrap();
    let want: Vec<_> = all.iter().filter(|r| r.lane == 1).collect();
    let bytes = stream(&lane1, 9, None);
    let (_, only) = parse_stream(&bytes).unwrap();
    assert!(want.len() > 1_000);
    // The headers differ only in the config digest; the records are the same bytes.
    assert_eq!(only.iter().collect::<Vec<_>>(), want);
}

#[test]
fn realized_mix_follows_the_config() {
    let cfg = Config::parse(&mini("base", None)).unwrap();
    let mut g = Generator::new(&cfg, &opts(4)).unwrap();
    // The first phase only: full rate, base cross weight.
    let mut seen = 0u64;
    for p in g.by_ref() {
        if p.send_ns >= 2_000_000 {
            break;
        }
        seen += 1;
    }
    let s = g.stats();
    assert!(seen > 10_000 && s.msgs > 80_000, "{} msgs", s.msgs);
    let near = |got: u64, want: u64, tol: u64| got.abs_diff(want) <= tol;
    // Targets of 02 §6.4 in ppm, with a few points of room for the warm-up and the fallbacks.
    assert!(near(s.share_ppm(s.by_class[0]), 970_000, 8_000), "{s}");
    assert!(near(s.share_ppm(s.by_class[1]), 25_000, 4_000), "{s}");
    assert!(near(s.share_ppm(s.by_class[2]), 5_000, 2_000), "{s}");
    let joins = s.kind(MsgKind::Join) + s.kind(MsgKind::Replace);
    // Orders end only at their drawn expiry, so until the first lifetimes run out (2 ms here) some
    // cancel draws become joins: the cancel share starts low and the join share high, and the mix
    // controller of 02 §6.10 closes the gap in a real run.
    assert!(near(s.share_ppm(joins), 500_000, 60_000), "{s}");
    assert!(
        near(s.share_ppm(s.kind(MsgKind::Cancel)), 450_000, 60_000),
        "{s}"
    );
    assert!(
        near(s.share_ppm(s.kind(MsgKind::Improve)), 20_000, 4_000),
        "{s}"
    );
    assert!(
        near(s.share_ppm(s.kind(MsgKind::Cross)), 10_000, 2_500),
        "{s}"
    );
    // 11.5% of join-class messages are Replaces (02 §6.4).
    let rep = s.kind(MsgKind::Replace) * 1_000 / joins;
    assert!((90..=140).contains(&rep), "replace per mille {rep}");
}

#[test]
fn phases_scale_the_rate_and_the_cross_weight() {
    let cfg = Config::parse(&mini("base", None)).unwrap();
    let mut in_phase = [0u64; 2];
    let mut crosses = [0u64; 2];
    for p in Generator::new(&cfg, &opts(5)).unwrap() {
        let ph = usize::from(p.send_ns >= 2_000_000);
        in_phase[ph] += 1;
        for m in Request::parse(p.bytes()).unwrap().msgs() {
            // A cross is a New that is not post-only with IOC or FOK, or a day order on the far side;
            // here the mini config's joins are all Day, so IOC and FOK identify crosses.
            if let Ok(Msg::New { flags, .. }) = m
                && flags.tif != vyrn_wire::Tif::Day
            {
                crosses[ph] += 1;
            }
        }
    }
    // The second phase runs at half rate: about half the packets, and no IOC/FOK crosses.
    assert!(
        in_phase[1] * 3 > in_phase[0] && in_phase[1] * 3 < in_phase[0] * 2,
        "{in_phase:?}"
    );
    assert!(crosses[0] > 50, "{crosses:?}");
    // cross_scale 0 leaves only day crosses (25% of crosses), which look like joins; the IOC/FOK
    // ones are gone.
    assert_eq!(crosses[1], 0);
}

#[test]
fn population_shape_follows_the_placement() {
    let cfg = Config::parse(&mini("base", None)).unwrap();
    let mut lanes: BTreeMap<u8, Vec<u32>> = BTreeMap::new();
    for p in Generator::new(&cfg, &opts(6)).unwrap() {
        let sid = Request::parse(p.bytes()).unwrap().header().session();
        let e = lanes.entry(p.lane.0).or_default();
        if !e.contains(&sid.0) {
            e.push(sid.0);
        }
    }
    // Dedicated lanes 0 and 1 hold two MM sessions each; the pool (lanes 10-12) holds the 8 pooled
    // sessions, spread by expected cross rate.
    assert_eq!(
        lanes.keys().copied().collect::<Vec<_>>(),
        [0, 1, 10, 11, 12]
    );
    assert_eq!(lanes[&0].len(), 2);
    assert_eq!(lanes[&1].len(), 2);
    let pool: usize = [10, 11, 12].iter().map(|l| lanes[l].len()).sum();
    assert_eq!(pool, 8);
    assert!(
        [10, 11, 12]
            .iter()
            .all(|l| (1..=4).contains(&lanes[l].len()))
    );
    // Slots count from 0 on each lane and the generation is 0.
    for (lane, sids) in &lanes {
        let mut slots: Vec<u32> = sids.iter().map(|s| s & 0xFFF).collect();
        slots.sort_unstable();
        assert_eq!(
            slots,
            (0..u32::try_from(sids.len()).unwrap()).collect::<Vec<_>>()
        );
        assert!(
            sids.iter()
                .all(|&s| s >> 20 == 0 && session_lane(SessionId(s)) == LaneId(*lane))
        );
    }
}

#[test]
fn bad_configs_and_streams_are_rejected() {
    let ok = mini("base", None);
    assert!(Config::parse(&ok).is_ok());
    let bad = |from: &str, to: &str| {
        Config::parse(&ok.replace(from, to))
            .unwrap_err()
            .to_string()
    };
    assert!(bad("version = 1", "version = 2").contains("version 2"));
    assert!(bad("spread_ticks = 2", "spred_ticks = 2").contains("spred_ticks"));
    assert!(bad("ppm = 400_000", "ppm = 400_001").contains("join_distance"));
    assert!(bad("bundle_size = 10", "bundle_size = 11").contains("bundle_size"));
    assert!(bad("lanes = 3", "lanes = 0").contains("pool"));
    assert!(bad("first_lane = 10", "first_lane = 1").contains("overlap"));
    let cfg = Config::parse(&ok).unwrap();
    let bytes = stream(&cfg, 1, Some(3));
    let mut wrong = bytes.clone();
    wrong[0] = b'X';
    assert_eq!(parse_stream(&wrong).unwrap_err(), StreamError::BadMagic);
    let mut v2 = bytes.clone();
    v2[8] = 2;
    assert_eq!(parse_stream(&v2).unwrap_err(), StreamError::Version(2));
    assert_eq!(
        parse_stream(&bytes[..bytes.len() - 1]).unwrap_err(),
        StreamError::Truncated
    );
    // Extensions are ignored by v1 readers, but unknown keys elsewhere are not.
    let with_ext = format!("{ok}\n[extensions]\nfuture = 1\n");
    assert!(Config::parse(&with_ext).is_ok());
    assert_eq!(Mode::Base, cfg.mode);
}

/// Bursts whose windows overlap (here 60 s windows at 2000 bursts/s over a 4 ms run) merge into
/// one window up to the end of the run; generating them must not look past it.
#[test]
fn overlapping_bursts_terminate_at_the_run_end() {
    let base = mini("base", None);
    let long = base.replace("window_ns = 100_000", "window_ns = 60_000_000_000");
    let off = base.replace("rate_per_s = 2000", "rate_per_s = 0");
    let count = |text: &str| {
        Generator::new(&Config::parse(text).unwrap(), &opts(3))
            .unwrap()
            .count()
    };
    let (n_long, n_off) = (count(&long), count(&off));
    // Bursty classes send at 2x for most of the run, so well over the burst-free count.
    assert!(n_long * 10 > n_off * 14, "{n_long} vs {n_off}");
}

/// 02 §6.7: an order ends at its drawn expiry, never before. With every lifetime set to 1 ms and
/// a 2 ms run, no cancel or replace may reach an order before 1 ms.
#[test]
fn nothing_is_canceled_or_replaced_before_its_lifetime() {
    let base = mini("base", None);
    let fixed = base
        .replace(
            "lo_ns = 5_000\nhi_ns = 100_000",
            "lo_ns = 1_000_000\nhi_ns = 1_000_001",
        )
        .replace(
            "lo_ns = 100_000\nhi_ns = 1_000_000",
            "lo_ns = 1_000_000\nhi_ns = 1_000_001",
        )
        .replace(
            "lo_ns = 1_000_000\nhi_ns = 100_000_000",
            "lo_ns = 1_000_000\nhi_ns = 1_000_001",
        )
        .replace(
            "lo_ns = 100_000_000\nhi_ns = 28_800_000_000_000",
            "lo_ns = 1_000_000\nhi_ns = 1_000_001",
        );
    // No reduces (a reduce of a one-lot order is sent as a cancel, 02 §6.6) and no live cap in reach.
    let fixed = fixed
        .replace(
            "join = 490_000, cancel = 442_000, reduce = 20_000",
            "join = 510_000, cancel = 442_000, reduce = 0",
        )
        .replace(
            "qty_p_ppm = 200_000\n",
            "qty_p_ppm = 200_000\nmax_live_orders = 1_000_000\n",
        );
    assert_ne!(fixed, base);
    let cfg = Config::parse(&fixed).unwrap();
    let (mut early, mut late) = (0, 0);
    for p in Generator::new(&cfg, &opts(8)).unwrap() {
        for m in Request::parse(p.bytes()).unwrap().msgs() {
            if matches!(m, Ok(Msg::Cancel { .. } | Msg::Replace { .. })) {
                if p.send_ns < 1_000_000 {
                    early += 1;
                } else {
                    late += 1;
                }
            }
        }
    }
    assert!(late > 1_000, "{late}");
    assert_eq!(early, 0, "{early} early vs {late} late");
}
