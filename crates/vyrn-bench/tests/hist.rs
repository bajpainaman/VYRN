//! Latency histograms: 11 §7.1 rule 5 and the VYRN-HIST v1 export.

use vyrn_bench::hist::{HDR_MAX_NS, HistError, LatencyHist, Req};

fn req(n: u32) -> Req {
    Req {
        session: n,
        pkt_seq: n + 1,
        index: u8::try_from(n % 10).unwrap(),
    }
}

#[test]
fn quantiles_are_exact_at_one_ns_up_to_10_us() {
    let mut h = LatencyHist::new();
    for v in 1..=HDR_MAX_NS {
        h.record(v, req(1));
    }
    assert_eq!(h.count(), HDR_MAX_NS);
    // Every value is its own bucket: no rounding to a coarser resolution.
    assert_eq!(h.value_at_ppm(500_000), Some(5_000));
    assert_eq!(h.value_at_ppm(990_000), Some(9_900));
    assert_eq!(h.value_at_ppm(999_000), Some(9_990));
    assert_eq!(h.value_at_ppm(1_000_000), Some(10_000));
    assert_eq!(h.value_at_ppm(1), Some(1));
    let text = h.export("exact").unwrap();
    assert_eq!(text.lines().filter(|l| l.starts_with("b ")).count(), 10_000);
    assert!(text.contains("\nb 7777 1\n"));
}

#[test]
fn samples_above_10_us_are_kept_exactly_never_clipped() {
    let mut h = LatencyHist::new();
    for _ in 0..990 {
        h.record(600, req(2));
    }
    h.record(10_001, req(3));
    h.record(47_321, req(4));
    h.record(5_000_000_123, req(5));
    for v in [12_345, 12_345] {
        h.record(v, req(6));
    }
    assert_eq!(h.count(), 995);
    let o: Vec<u64> = h.overflow().iter().map(|s| s.value_ns).collect();
    assert_eq!(o, [10_001, 12_345, 12_345, 47_321, 5_000_000_123]);
    // Rank = ceil(995 × q): q = 99.5% is rank 991, the first overflow sample; q = 99.9% is rank
    // 995, the largest. Both are exact, not bucket-rounded.
    assert_eq!(h.value_at_ppm(995_000), Some(10_001));
    assert_eq!(h.value_at_ppm(997_000), Some(12_345));
    assert_eq!(h.value_at_ppm(999_000), Some(5_000_000_123));
    assert_eq!(h.value_at_ppm(1_000_000), Some(5_000_000_123));
    assert_eq!(h.max().unwrap().req, req(5));
}

#[test]
fn max_keeps_the_smallest_request_among_equals_and_is_order_independent() {
    let mut a = LatencyHist::new();
    let mut b = LatencyHist::new();
    for (v, r) in [(900, 7), (900, 3), (50, 1)] {
        a.record(v, req(r));
    }
    for (v, r) in [(50, 1), (900, 3), (900, 7)] {
        b.record(v, req(r));
    }
    assert_eq!(a.max(), b.max());
    assert_eq!(a.max().unwrap().req, req(3));
    assert_eq!(a.export("x").unwrap(), b.export("x").unwrap());
}

#[test]
fn export_round_trips_and_merge_adds() {
    let mut h = LatencyHist::new();
    for i in 0..500u32 {
        h.record(u64::from(i % 97) * 31 + 560, req(i));
    }
    h.record(20_000, req(900));
    let text = h.export("b3-lane0").unwrap();
    let (name, back) = LatencyHist::parse(&text).unwrap();
    assert_eq!(name, "b3-lane0");
    assert_eq!(back.export("b3-lane0").unwrap(), text);
    assert_eq!(back.max(), h.max());
    let mut m = LatencyHist::new();
    m.merge(&h);
    m.merge(&back);
    assert_eq!(m.count(), 2 * h.count());
    assert_eq!(m.overflow().len(), 2);
    assert_eq!(m.value_at_ppm(500_000), h.value_at_ppm(500_000));
}

#[test]
fn empty_and_malformed_exports() {
    let h = LatencyHist::new();
    assert_eq!(h.value_at_ppm(500_000), None);
    let text = h.export("empty").unwrap();
    assert_eq!(
        text,
        "vyrn-hist 1\nname empty\nunit ns\nhdr_max_ns 10000\ncount 0\n"
    );
    assert!(LatencyHist::parse(&text).is_ok());
    assert_eq!(h.export("has space").unwrap_err(), HistError::Name);
    let mut one = LatencyHist::new();
    one.record(100, req(1));
    let good = one.export("x").unwrap();
    assert_eq!(
        LatencyHist::parse(&good.replace("count 1", "count 2")).unwrap_err(),
        HistError::Count {
            stated: 2,
            actual: 1
        }
    );
    assert_eq!(
        LatencyHist::parse(&good.replace("max 100 ", "max 101 ")).unwrap_err(),
        HistError::Max
    );
    assert_eq!(
        LatencyHist::parse(&good.replace("vyrn-hist 1", "vyrn-hist 2")).unwrap_err(),
        HistError::Header
    );
    assert!(matches!(
        LatencyHist::parse(&good.replace("b 100 1", "b 100 0")),
        Err(HistError::Line(_))
    ));
    assert!(matches!(
        LatencyHist::parse(&format!("{good}o 9000 1 1 1\n")),
        Err(HistError::Line(_))
    ));
}

#[test]
fn an_overflow_max_must_name_a_request_that_is_in_the_samples() {
    let mut h = LatencyHist::new();
    h.record(20_000, req(1));
    h.record(20_000, req(9));
    h.record(15_000, req(5));
    let good = h.export("x").unwrap();
    assert!(LatencyHist::parse(&good).is_ok());
    assert!(good.contains("\nmax 20000 1 2 1\n"));
    // A request that is not in the overflow list, one that is but is not the smallest among the
    // equal maxima, and one that belongs to a smaller sample.
    for wrong in ["max 20000 7 8 7", "max 20000 9 10 9", "max 20000 5 6 5"] {
        let text = good.replace("max 20000 1 2 1", wrong);
        assert_eq!(
            LatencyHist::parse(&text).unwrap_err(),
            HistError::Max,
            "{wrong}"
        );
    }
}
