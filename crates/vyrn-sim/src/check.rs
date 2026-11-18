//! Invariant checkers (11 §6.4 "Invariants checked continuously").
//!
//! A [`Checker`] reads a stream of [`Obs`] and stops at the first broken invariant. The
//! observations are plain values with a text form ([`Obs::parse`]), so another implementation
//! can run `tests/golden/sim_checks.txt` against its own checker: each case is a list of
//! observations and the verdict (`ok`, or the check name and the 0-based observation index).
//!
//! | check | observation | rule |
//! |---|---|---|
//! | `INV-CUT-MONO` | `step` | every lane's cut entry is ≥ its value in every earlier step (01 §14.3) |
//! | `STEP-FILL-CAP` | `step` | `n_fills` ≤ [`STEP_FILL_CAP`] (01 §14.15 item 6) |
//! | `INV-UNCROSSED` | `snap` | `bid < ask`, or no bid (0), or no ask (`u32::MAX`) |
//! | `SHED-LOGGED` | `busy` | a `pkt` record with `SHED` for the same session and `pkt_seq` came before it |
//! | `SESSION-ORDER` | `resp` | in-stream `resp_seq` (non-zero) is strictly increasing per session |
//!
//! `SESSION-ORDER` is weaker than 11 §6.4's "gapless": fill TX packets take `MakerSeq` numbers
//! that the lane's `resp_seq` count does not show the sim, so gaps are allowed (spec gap, PR).

use std::collections::{BTreeMap, BTreeSet};

/// No step writes more than this many fill records (01 §14.15 item 6).
pub const STEP_FILL_CAP: u32 = 64;

/// One observation of the live run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Obs {
    /// A step record: its id, fill count and changed cut entries `(lane, seq)`.
    Step {
        step: u64,
        n_fills: u32,
        cut: Vec<(u8, u64)>,
    },
    /// The BBO snapshot after a step.
    Snap { bid: u32, ask: u32 },
    /// A packet record: session, `pkt_seq`, and whether `SHED` is set.
    Pkt {
        session: u32,
        pkt_seq: u32,
        shed: bool,
    },
    /// The lane returned `Shed` (`BUSY` for every message) for this packet.
    Busy { session: u32, pkt_seq: u32 },
    /// A response packet (lane or fill TX) with its `resp_seq` (0 = out of stream).
    Resp { session: u32, resp_seq: u32 },
}

/// The first broken check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub check: &'static str,
    /// Index of the observation (in a checker) or the event (in a run).
    pub index: u64,
    pub detail: String,
}

/// Running state of every per-observation check.
#[derive(Default, Debug)]
pub struct Checker {
    cut: BTreeMap<u8, u64>,
    shed: BTreeSet<(u32, u32)>,
    resp: BTreeMap<u32, u32>,
    seen: u64,
}

impl Checker {
    /// Checks `o`. `Err` carries the check name and a detail; the caller adds the index.
    pub fn observe(&mut self, o: &Obs) -> Result<(), (&'static str, String)> {
        self.seen = self.seen.saturating_add(1);
        match o {
            Obs::Step { step, n_fills, cut } => {
                if *n_fills > STEP_FILL_CAP {
                    return Err(("STEP-FILL-CAP", format!("step {step} n_fills {n_fills}")));
                }
                for (l, s) in cut {
                    let prev = self.cut.entry(*l).or_insert(0);
                    if *s < *prev {
                        return Err((
                            "INV-CUT-MONO",
                            format!("step {step} lane {l} cut {s} < {prev}"),
                        ));
                    }
                    *prev = *s;
                }
            }
            Obs::Snap { bid, ask } => {
                if *bid != 0 && *ask != u32::MAX && bid >= ask {
                    return Err(("INV-UNCROSSED", format!("bid {bid} ask {ask}")));
                }
            }
            Obs::Pkt {
                session,
                pkt_seq,
                shed,
            } => {
                if *shed {
                    self.shed.insert((*session, *pkt_seq));
                }
            }
            Obs::Busy { session, pkt_seq } => {
                if !self.shed.contains(&(*session, *pkt_seq)) {
                    return Err((
                        "SHED-LOGGED",
                        format!("session {session} pkt_seq {pkt_seq} has no SHED record"),
                    ));
                }
            }
            Obs::Resp { session, resp_seq } => {
                if *resp_seq != 0 {
                    let prev = self.resp.entry(*session).or_insert(0);
                    if *resp_seq <= *prev {
                        return Err((
                            "SESSION-ORDER",
                            format!("session {session} resp_seq {resp_seq} after {prev}"),
                        ));
                    }
                    *prev = *resp_seq;
                }
            }
        }
        Ok(())
    }
}

fn num<T: std::str::FromStr>(t: Option<&str>) -> Result<T, String> {
    let t = t.ok_or("missing field")?;
    t.parse().map_err(|_| format!("bad number {t:?}"))
}

impl Obs {
    /// Parses one line: `step <id> <n_fills> [lane:seq,...]`, `snap <bid> <ask>`,
    /// `pkt <session> <pkt_seq> <0|1 shed>`, `busy <session> <pkt_seq>`,
    /// `resp <session> <resp_seq>`. `ask` may be `none` (`u32::MAX`).
    pub fn parse(line: &str) -> Result<Self, String> {
        let mut t = line.split_whitespace();
        let kind = t.next().ok_or("empty line")?;
        Ok(match kind {
            "step" => {
                let step = num(t.next())?;
                let n_fills = num(t.next())?;
                let mut cut = Vec::new();
                if let Some(c) = t.next() {
                    for e in c.split(',') {
                        let (l, s) = e.split_once(':').ok_or("cut entry is lane:seq")?;
                        cut.push((num(Some(l))?, num(Some(s))?));
                    }
                }
                Self::Step { step, n_fills, cut }
            }
            "snap" => {
                let bid = num(t.next())?;
                let ask = match t.next() {
                    Some("none") => u32::MAX,
                    a => num(a)?,
                };
                Self::Snap { bid, ask }
            }
            "pkt" => Self::Pkt {
                session: num(t.next())?,
                pkt_seq: num(t.next())?,
                shed: num::<u8>(t.next())? == 1,
            },
            "busy" => Self::Busy {
                session: num(t.next())?,
                pkt_seq: num(t.next())?,
            },
            "resp" => Self::Resp {
                session: num(t.next())?,
                resp_seq: num(t.next())?,
            },
            k => return Err(format!("unknown observation {k:?}")),
        })
    }
}

/// Runs `obs` through a fresh checker: `None`, or the first violation with its index.
pub fn check_all(obs: &[Obs]) -> Option<Violation> {
    let mut c = Checker::default();
    for (i, o) in obs.iter().enumerate() {
        if let Err((check, detail)) = c.observe(o) {
            return Some(Violation {
                check,
                index: u64::try_from(i).unwrap_or(u64::MAX),
                detail,
            });
        }
    }
    None
}
