//! `trace-dump`: the offline reader of the per-core trace rings (spec/11-build.md §8.3, §3.8).
//!
//! # Contract
//!
//! - **Writer:** each pinned core writes its own ring, a file of fixed 16-byte entries at
//!   `/dev/hugepages/vyrn-trace-<pid>-<core>`, overwriting the oldest entry. The control core
//!   records a (TSC, PHC) pair each second. The process may be gone when the rings are read.
//! - **Readers:** this tool and `vyrn-admin trace dump` (§1.3). This crate is the reference
//!   decoder; a second reader must print the same lines for the vectors in `fixtures/`.
//! - **Entry layout** (little-endian, 01 §2):
//!
//!   | off | size | field |
//!   |---|---|---|
//!   | 0 | 8 | `tsc` u64 |
//!   | 8 | 1 | `kind` u8 |
//!   | 9 | 1 | `core` u8 |
//!   | 10 | 2 | `arg16` u16 |
//!   | 12 | 4 | `arg32` u32 |
//!
//!   A ring file is any whole number of entries (65,536 in production, `BLD_TRACE_ENTRIES`). An
//!   all-zero entry is a slot never written and is skipped.
//! - **Kinds:** [`KINDS`] gives the codes. §8.3 names the kinds but not their numbers; the
//!   numbering here is this crate's choice, in §8.3's order, until 01 or 11 fixes it. An unknown
//!   code prints as `KIND_<n>`.
//! - **Ordering:** the ring has no head index, so entries of all given files are merged and
//!   sorted by `tsc`, then `core`, then file order, then slot. TSC is invariant and shared by
//!   all cores of one box (06), so one sort orders the whole box.
//! - **Clock file** (optional): one `<tsc> <ptp_ns>` pair per line, decimal, `#` comments
//!   allowed, `tsc` strictly increasing. A TSC is converted by linear interpolation on the two
//!   pairs that bracket it, or on the first or last two pairs outside the range, rounding toward
//!   zero, in integer arithmetic. With fewer than two pairs, or with no clock file, the time
//!   column is `-`.
//! - **Output:** one line per entry, `<ptp_ns|-> tsc=<tsc> core=<core> <KIND> arg16=<n> arg32=<n>`.
//!
//! ```text
//! trace-dump [--clock FILE] RING...
//! ```
//!
//! Exit status: 0 dumped, 2 the input is rejected. Reject reasons, on stderr:
//!
//! | reason | meaning |
//! |---|---|
//! | `ring-size` | a ring file's length is not a multiple of 16 |
//! | `clock-syntax` | a clock line is not two decimal integers |
//! | `clock-order` | a clock line's `tsc` is not greater than the previous line's |
//!
//! Conformance vectors: `tools/trace-dump/fixtures/*/` (`args.txt`, ring files, `expected.txt`).
#![forbid(unsafe_code)]

/// Bytes per entry (§8.3).
pub const ENTRY_BYTES: usize = 16;

/// Kind codes, in §8.3's order. Code 0 is never written.
pub const KINDS: &[(u8, &str)] = &[
    (1, "RX_PKT"),
    (2, "STEP_BEGIN"),
    (3, "STEP_END"),
    (4, "CUT"),
    (5, "RING_FULL"),
    (6, "REJECT"),
    (7, "STALL"),
    (8, "SEAL"),
    (9, "PANIC"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub tsc: u64,
    pub core: u8,
    pub kind: u8,
    pub arg16: u16,
    pub arg32: u32,
}

/// The name of a kind code.
pub fn kind_name(kind: u8) -> String {
    KINDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or_else(|| format!("KIND_{kind}"), |(_, n)| (*n).to_owned())
}

/// Decodes one ring file. Rejects a length that is not a whole number of entries.
pub fn decode(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    if !bytes.len().is_multiple_of(ENTRY_BYTES) {
        return Err(format!(
            "ring-size: {} bytes is not a multiple of {ENTRY_BYTES}",
            bytes.len()
        ));
    }
    let mut out = Vec::new();
    for &e in bytes.as_chunks::<ENTRY_BYTES>().0 {
        if e == [0; ENTRY_BYTES] {
            continue;
        }
        let [
            t0,
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
            t7,
            kind,
            core,
            a0,
            a1,
            b0,
            b1,
            b2,
            b3,
        ] = e;
        out.push(Entry {
            tsc: u64::from_le_bytes([t0, t1, t2, t3, t4, t5, t6, t7]),
            core,
            kind,
            arg16: u16::from_le_bytes([a0, a1]),
            arg32: u32::from_le_bytes([b0, b1, b2, b3]),
        });
    }
    Ok(out)
}

/// Parses a clock file into strictly increasing `(tsc, ptp_ns)` pairs.
pub fn parse_clock(text: &str) -> Result<Vec<(u64, u64)>, String> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let pair = match (it.next(), it.next(), it.next()) {
            (Some(a), Some(b), None) => a.parse().ok().zip(b.parse().ok()),
            _ => None,
        };
        let Some((tsc, ptp)) = pair else {
            return Err(format!(
                "clock-syntax: line {}: want `<tsc> <ptp_ns>`",
                i + 1
            ));
        };
        if out.last().is_some_and(|&(t, _)| t >= tsc) {
            return Err(format!(
                "clock-order: line {}: tsc does not increase",
                i + 1
            ));
        }
        out.push((tsc, ptp));
    }
    Ok(out)
}

/// TSC to PTP ns on the pairs of [`parse_clock`]; `None` with fewer than two pairs or when the
/// result is outside `u64`.
pub fn to_ptp(clock: &[(u64, u64)], tsc: u64) -> Option<u64> {
    if clock.len() < 2 {
        return None;
    }
    let k = clock
        .partition_point(|&(t, _)| t <= tsc)
        .clamp(1, clock.len() - 1);
    let (t0, p0) = *clock.get(k - 1)?;
    let (t1, p1) = *clock.get(k)?;
    let (t0, p0, t1, p1, x) = (
        i128::from(t0),
        i128::from(p0),
        i128::from(t1),
        i128::from(p1),
        i128::from(tsc),
    );
    let ns = p0 + (x - t0) * (p1 - p0) / (t1 - t0);
    u64::try_from(ns).ok()
}

/// Merges the rings (in file order) and prints the dump lines.
pub fn dump(rings: &[Vec<Entry>], clock: &[(u64, u64)]) -> Vec<String> {
    let mut all: Vec<(u64, u8, usize, usize, Entry)> = rings
        .iter()
        .enumerate()
        .flat_map(|(f, r)| {
            r.iter()
                .enumerate()
                .map(move |(s, e)| (e.tsc, e.core, f, s, *e))
        })
        .collect();
    all.sort();
    all.into_iter()
        .map(|(_, _, _, _, e)| {
            let t = to_ptp(clock, e.tsc).map_or_else(|| "-".to_owned(), |n| n.to_string());
            format!(
                "{t} tsc={} core={} {} arg16={} arg32={}",
                e.tsc,
                e.core,
                kind_name(e.kind),
                e.arg16,
                e.arg32
            )
        })
        .collect()
}
