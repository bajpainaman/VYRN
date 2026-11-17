//! Latency histograms and their export, `VYRN-HIST` v1 (`bench/workloads/FORMAT.md`).
//!
//! 11 §7.1 rule 5: complete HDR histograms with 1 ns resolution up to 10 µs, the maximum kept
//! exactly with the request that produced it, and every sample above 10 µs kept in an overflow
//! list, never clipped. Rule 8: the signed report carries the raw histograms, so the export keeps
//! raw counts. Integer arithmetic throughout.
//!
//! ```text
//! vyrn-hist 1
//! name <token>                one token, no spaces
//! unit ns
//! hdr_max_ns 10000
//! count <n>                   samples in b lines plus o lines
//! max <ns> <session> <pkt_seq> <index>      absent when count is 0
//! b <ns> <count>              one line per recorded value ≤ hdr_max_ns, ascending
//! o <ns> <session> <pkt_seq> <index>        one line per sample above hdr_max_ns, ascending
//! ```
#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]

use std::fmt::Write as _;

use hdrhistogram::Histogram;
use thiserror::Error;

pub const HIST_VERSION: u32 = 1;
/// Samples up to here go into the HDR histogram; larger ones go to the overflow list.
pub const HDR_MAX_NS: u64 = 10_000;
/// Four significant figures give 1 ns buckets up to 32,767 ns.
const SIGFIG: u8 = 4;

/// The request a latency sample belongs to: the packet and the message index in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Req {
    pub session: u32,
    pub pkt_seq: u32,
    pub index: u8,
}

/// Ordered by value, then request, so that every list is canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sample {
    pub value_ns: u64,
    pub req: Req,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HistError {
    #[error("not a vyrn-hist v{HIST_VERSION} export")]
    Header,
    #[error("line {0} is malformed")]
    Line(usize),
    #[error("count line says {stated}, the body holds {actual}")]
    Count { stated: u64, actual: u64 },
    #[error("the max line does not match the largest sample")]
    Max,
    #[error("name must be one token without whitespace")]
    Name,
}

#[derive(Clone, Debug)]
pub struct LatencyHist {
    hdr: Histogram<u64>,
    overflow: Vec<Sample>,
    max: Option<Sample>,
}

impl Default for LatencyHist {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHist {
    pub fn new() -> Self {
        // The bounds are constants the crate accepts.
        let hdr = Histogram::new_with_bounds(1, HDR_MAX_NS, SIGFIG)
            .unwrap_or_else(|_| Histogram::new(SIGFIG).unwrap_or_else(|_| unreachable!()));
        Self {
            hdr,
            overflow: Vec::new(),
            max: None,
        }
    }

    pub fn record(&mut self, value_ns: u64, req: Req) {
        self.add(Sample { value_ns, req }, 1);
    }

    fn add(&mut self, s: Sample, n: u64) {
        if s.value_ns <= HDR_MAX_NS {
            // record_n fails only above the trackable range, which the branch excludes.
            let _ = self.hdr.record_n(s.value_ns, n);
        } else {
            for _ in 0..n {
                let at = self.overflow.partition_point(|o| *o < s);
                self.overflow.insert(at, s);
            }
        }
        let better = match self.max {
            None => true,
            Some(m) => s.value_ns > m.value_ns || (s.value_ns == m.value_ns && s.req < m.req),
        };
        if better {
            self.max = Some(s);
        }
    }

    pub fn count(&self) -> u64 {
        self.hdr.len() + u64::try_from(self.overflow.len()).unwrap_or(u64::MAX)
    }

    /// The largest sample, with its request (the smallest request among equals).
    pub fn max(&self) -> Option<Sample> {
        self.max
    }

    /// Samples above `HDR_MAX_NS`, ascending.
    pub fn overflow(&self) -> &[Sample] {
        &self.overflow
    }

    /// The smallest recorded value v such that at least `q_ppm` / 10⁶ of the samples are ≤ v.
    pub fn value_at_ppm(&self, q_ppm: u32) -> Option<u64> {
        let total = self.count();
        if total == 0 {
            return None;
        }
        let rank = (u128::from(total) * u128::from(q_ppm))
            .div_ceil(1_000_000)
            .max(1);
        let mut seen = 0u128;
        for v in self.hdr.iter_recorded() {
            seen += u128::from(v.count_at_value());
            if seen >= rank {
                return Some(v.value_iterated_to());
            }
        }
        for s in &self.overflow {
            seen += 1;
            if seen >= rank {
                return Some(s.value_ns);
            }
        }
        self.max.map(|m| m.value_ns)
    }

    pub fn merge(&mut self, other: &Self) {
        for v in other.hdr.iter_recorded() {
            // Counts at one value carry no request; the max below does.
            let _ = self.hdr.record_n(v.value_iterated_to(), v.count_at_value());
        }
        for s in &other.overflow {
            self.add(*s, 1);
        }
        if let Some(m) = other.max
            && self.max.is_none_or(|a| {
                m.value_ns > a.value_ns || (m.value_ns == a.value_ns && m.req < a.req)
            })
        {
            self.max = Some(m);
        }
    }

    pub fn export(&self, name: &str) -> Result<String, HistError> {
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(HistError::Name);
        }
        let mut s = format!(
            "vyrn-hist {HIST_VERSION}\nname {name}\nunit ns\nhdr_max_ns {HDR_MAX_NS}\ncount {}\n",
            self.count()
        );
        if let Some(m) = self.max {
            let _ = writeln!(
                s,
                "max {} {} {} {}",
                m.value_ns, m.req.session, m.req.pkt_seq, m.req.index
            );
        }
        for v in self.hdr.iter_recorded() {
            let _ = writeln!(s, "b {} {}", v.value_iterated_to(), v.count_at_value());
        }
        for o in &self.overflow {
            let _ = writeln!(
                s,
                "o {} {} {} {}",
                o.value_ns, o.req.session, o.req.pkt_seq, o.req.index
            );
        }
        Ok(s)
    }

    /// Reads an export. Returns its name and the histogram.
    pub fn parse(text: &str) -> Result<(String, Self), HistError> {
        let mut lines = text.lines().enumerate();
        let mut next = |key: &str| -> Result<(usize, Vec<&str>), HistError> {
            let (i, l) = lines.next().ok_or(HistError::Header)?;
            let f: Vec<&str> = l.split(' ').collect();
            if f.first() != Some(&key) {
                return Err(HistError::Header);
            }
            Ok((i + 1, f))
        };
        let (_, v) = next("vyrn-hist")?;
        if v.get(1).copied() != Some("1") || v.len() != 2 {
            return Err(HistError::Header);
        }
        let (_, n) = next("name")?;
        let name = match n.as_slice() {
            [_, name] => (*name).to_owned(),
            _ => return Err(HistError::Header),
        };
        let (_, u) = next("unit")?;
        let (_, m) = next("hdr_max_ns")?;
        if u.get(1).copied() != Some("ns")
            || m.get(1).and_then(|x| x.parse::<u64>().ok()) != Some(HDR_MAX_NS)
        {
            return Err(HistError::Header);
        }
        let (ci, c) = next("count")?;
        let stated: u64 = c
            .get(1)
            .and_then(|x| x.parse().ok())
            .ok_or(HistError::Line(ci))?;
        let mut h = Self::new();
        let mut stated_max: Option<Sample> = None;
        for (i, l) in lines {
            let no = i + 1;
            let f: Vec<&str> = l.split(' ').collect();
            let num = |k: usize| {
                f.get(k)
                    .and_then(|x| x.parse::<u64>().ok())
                    .ok_or(HistError::Line(no))
            };
            let req = |k: usize| -> Result<Req, HistError> {
                Ok(Req {
                    session: u32::try_from(num(k)?).map_err(|_| HistError::Line(no))?,
                    pkt_seq: u32::try_from(num(k + 1)?).map_err(|_| HistError::Line(no))?,
                    index: u8::try_from(num(k + 2)?).map_err(|_| HistError::Line(no))?,
                })
            };
            match (f.first().copied(), f.len()) {
                (Some("max"), 5) => {
                    stated_max = Some(Sample {
                        value_ns: num(1)?,
                        req: req(2)?,
                    });
                }
                (Some("b"), 3) => {
                    let (v, n) = (num(1)?, num(2)?);
                    if v > HDR_MAX_NS || n == 0 {
                        return Err(HistError::Line(no));
                    }
                    h.hdr.record_n(v, n).map_err(|_| HistError::Line(no))?;
                }
                (Some("o"), 5) => {
                    let s = Sample {
                        value_ns: num(1)?,
                        req: req(2)?,
                    };
                    if s.value_ns <= HDR_MAX_NS {
                        return Err(HistError::Line(no));
                    }
                    h.overflow.push(s);
                }
                _ => return Err(HistError::Line(no)),
            }
        }
        h.overflow.sort();
        if h.count() != stated {
            return Err(HistError::Count {
                stated,
                actual: h.count(),
            });
        }
        // The exact max is a statement of the export. Above 10 us the body holds its request, so
        // the line must name the smallest request among the equal largest samples; in the 1 ns
        // buckets a count carries no request, so only the value is checked.
        let top = h.overflow.last().map(|s| s.value_ns);
        let largest_body =
            top.or_else(|| h.hdr.iter_recorded().last().map(|v| v.value_iterated_to()));
        let canonical = top.and_then(|v| h.overflow.iter().find(|s| s.value_ns == v).copied());
        match (stated_max, largest_body) {
            (None, None) => {}
            (Some(m), Some(l)) if m.value_ns == l && canonical.is_none_or(|c| c == m) => {
                h.max = Some(m);
            }
            _ => return Err(HistError::Max),
        }
        Ok((name, h))
    }
}
