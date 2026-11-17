//! Oracle scenarios (spec/11-build.md §5.2): event lists written by people from the text of 05,
//! 08 and 10, each with its expected records. The format is plain text, so any implementation
//! of the book can run the same files; `tests/golden/scenarios/README.md` defines it.

use crate::oracle::Oracle;
use crate::oracle_abi::{Account, Config, E_CAP, E_EVENT, E_FAULT, E_FULL, Event, Record, Session};
use std::collections::BTreeMap;
use std::path::Path;

fn num(t: &str) -> Result<u64, String> {
    let t = t.replace('_', "");
    let r = match t.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16),
        None => t.parse::<u64>(),
    };
    r.map_err(|_| format!("bad number {t:?}"))
}
fn signed(t: &str) -> Result<i64, String> {
    match t.strip_prefix('-') {
        Some(v) => i64::try_from(num(v)?)
            .map(|v| -v)
            .map_err(|e| e.to_string()),
        None => i64::try_from(num(t)?).map_err(|e| e.to_string()),
    }
}
fn n32(t: &str) -> Result<u32, String> {
    u32::try_from(num(t)?).map_err(|_| format!("{t:?} does not fit 32 bits"))
}
fn n8(t: &str) -> Result<u8, String> {
    u8::try_from(num(t)?).map_err(|_| format!("{t:?} does not fit 8 bits"))
}
/// `key=value` pairs of a line.
fn kv<'a>(toks: &[&'a str]) -> BTreeMap<&'a str, &'a str> {
    toks.iter().filter_map(|t| t.split_once('=')).collect()
}
fn get<'a>(m: &BTreeMap<&str, &'a str>, k: &str) -> Result<&'a str, String> {
    m.get(k).copied().ok_or_else(|| format!("missing {k}="))
}

fn phase(t: &str) -> Result<u8, String> {
    Ok(match t {
        "continuous" => 1,
        "auction" => 2,
        "halted" => 3,
        "frozen" => 4,
        _ => return Err(format!("unknown phase {t:?}")),
    })
}

/// Reject reasons (01 §6.5, §14.10) and Out causes (01 §14.10) by name.
fn code(t: &str) -> Result<u64, String> {
    const NAMES: &[(&str, u64)] = &[
        ("BAD_TYPE", 3),
        ("BAD_TICK", 4),
        ("BAD_QTY", 5),
        ("RISK_CREDIT", 6),
        ("RISK_ORDER_COUNT", 8),
        ("POST_ONLY_WOULD_CROSS", 10),
        ("FOK_UNFILLABLE", 11),
        ("UNKNOWN_HANDLE", 12),
        ("TOO_LATE", 13),
        ("BOOK_HALTED", 14),
        ("STP", 16),
        ("AUCTION_PHASE", 19),
        ("SIDE_MISMATCH", 20),
        ("BUSY", 24),
        ("ioc", 1),
        ("stp", 2),
        ("auction", 3),
        ("maker", 0xFF),
    ];
    NAMES
        .iter()
        .find(|(n, _)| *n == t)
        .map_or_else(|| num(t), |(_, c)| Ok(*c))
}

/// The 16 message bytes of an op (01 §6.2).
fn msg(toks: &[&str]) -> Result<[u8; 16], String> {
    let mut m = [0u8; 16];
    let put = |m: &mut [u8; 16], at: usize, v: u32| m[at..at + 4].copy_from_slice(&v.to_le_bytes());
    // `buy|sell day|ioc|fok|auction [post] [stp=N]` -> the flags byte and the rest of the tokens.
    let flags = |t: &[&str]| -> Result<(u8, usize), String> {
        let side = match t.first() {
            Some(&"buy") => 0,
            Some(&"sell") => 1,
            _ => return Err("expected buy or sell".into()),
        };
        let tif = match t.get(1) {
            Some(&"day") => 0,
            Some(&"ioc") => 1,
            Some(&"fok") => 2,
            Some(&"auction") => 3,
            _ => return Err("expected day, ioc, fok or auction".into()),
        };
        let (mut f, mut i) = (side | (tif << 1), 2);
        while let Some(t) = t.get(i) {
            if *t == "post" {
                f |= 8;
            } else if let Some(s) = t.strip_prefix("stp=") {
                f |= n8(s)? << 4;
            } else {
                break;
            }
            i += 1;
        }
        Ok((f, i))
    };
    let arg = |t: &[&str], i: usize| {
        t.get(i)
            .ok_or("missing operand".to_string())
            .and_then(|s| n32(s))
    };
    let rest = &toks[1..];
    match toks.first().copied() {
        Some("new") => {
            let (f, i) = flags(rest)?;
            m[0] = 1;
            m[1] = f;
            put(&mut m, 4, arg(rest, i)?);
            put(&mut m, 8, arg(rest, i + 1)?);
            put(&mut m, 12, arg(rest, i + 2)?);
        }
        Some("cancel") => {
            m[0] = 2;
            put(&mut m, 4, arg(rest, 0)?);
            put(&mut m, 12, arg(rest, 1)?);
        }
        Some("reduce") => {
            m[0] = 3;
            put(&mut m, 4, arg(rest, 0)?);
            put(&mut m, 8, arg(rest, 1)?);
            put(&mut m, 12, arg(rest, 2)?);
        }
        Some("replace") => {
            let (f, i) = flags(rest)?;
            m[0] = 4;
            m[1] = f;
            put(&mut m, 4, arg(rest, i)?);
            put(&mut m, 8, arg(rest, i + 1)?);
            put(&mut m, 12, arg(rest, i + 2)?);
        }
        Some("cancel_all") => {
            m[0] = 0x12;
            put(&mut m, 12, arg(rest, 0)?);
        }
        Some("heartbeat") => m[0] = 0x10,
        Some("raw") => {
            let h = rest.concat();
            if h.len() != 32 {
                return Err("raw needs 16 bytes of hex".into());
            }
            for (i, b) in m.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
            }
        }
        _ => return Err(format!("unknown op {:?}", toks.first())),
    }
    Ok(m)
}

/// One expected record (01 §6.4 bytes), from its name and fields.
fn record(toks: &[&str], vectors: &BTreeMap<String, Vec<[u8; 16]>>) -> Result<[u8; 16], String> {
    let f = |i: usize| {
        toks.get(i)
            .ok_or("missing field".to_string())
            .and_then(|t| code(t))
    };
    let (ty, w2, w4, w8, w12) = match toks.first().copied() {
        Some("vector") => {
            let v = toks.get(1).ok_or("missing vector name")?;
            let recs = vectors
                .get(*v)
                .ok_or(format!("no response {v} in the golden file"))?;
            let i = usize::try_from(f(2)?).map_err(|e| e.to_string())?;
            return recs.get(i).copied().ok_or(format!("{v} has no record {i}"));
        }
        Some("ack") => (0x81, 0, f(2)?, f(3)?, f(4)?),
        Some("fill") => (0x82, f(2)?, f(3)?, f(4)?, f(5)?),
        Some("reject") => (0x83, f(2)?, f(3)?, 0, f(4)?),
        Some("cancel_ack") => (0x84, 0, f(2)?, f(3)?, f(4)?),
        Some("out") => (0x85, f(2)?, f(3)?, f(4)?, f(5)?),
        _ => return Err(format!("unknown record {:?}", toks.first())),
    };
    let mut r = [0u8; 16];
    r[0] = ty;
    r[1] = u8::try_from(f(1)?).map_err(|e| e.to_string())?;
    r[2..4].copy_from_slice(&u16::try_from(w2).map_err(|e| e.to_string())?.to_le_bytes());
    for (at, v) in [(4, w4), (8, w8), (12, w12)] {
        r[at..at + 4].copy_from_slice(&u32::try_from(v).map_err(|e| e.to_string())?.to_le_bytes());
    }
    Ok(r)
}

/// The records of each response packet in the 04 §11 output (`vyrn_proto_vectors.out`).
pub fn golden_responses(out: &str) -> BTreeMap<String, Vec<[u8; 16]>> {
    let mut all = BTreeMap::new();
    let mut cur: Option<(String, bool, Vec<u8>)> = None;
    let done = |c: Option<(String, bool, Vec<u8>)>, all: &mut BTreeMap<_, _>| {
        if let Some((name, true, bytes)) = c {
            let n = usize::from(bytes[8]);
            let recs: Vec<[u8; 16]> = bytes[16..16 + 16 * n]
                .chunks(16)
                .map(|c| c.try_into().unwrap_or([0; 16]))
                .collect();
            all.insert(name, recs);
        }
    };
    for line in out.lines() {
        if line.starts_with('V') {
            done(cur.take(), &mut all);
            let name = line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            cur = Some((name, line.contains(" resp "), Vec::new()));
        } else if let (Some((_, _, b)), Some((off, hex))) =
            (cur.as_mut(), line.trim().split_once(": "))
            && off.len() == 3
            && off.chars().all(|c| c.is_ascii_hexdigit())
        {
            b.extend(
                hex.split_whitespace()
                    .filter_map(|h| u8::from_str_radix(h, 16).ok()),
            );
        }
    }
    done(cur, &mut all);
    all
}

struct Pending {
    line: usize,
    ev: Event,
    want: Vec<Record>,
    err: Option<u32>,
    none: bool,
}

/// Runs one scenario file against the oracle library at `lib`. `Err` names the first mismatch.
pub fn run(
    lib: &Path,
    text: &str,
    vectors: &BTreeMap<String, Vec<[u8; 16]>>,
) -> Result<usize, String> {
    let (mut cfg, mut accts, mut sess) = (Config::default(), Vec::new(), Vec::new());
    let mut oracle: Option<Oracle> = None;
    let mut pending: Option<Pending> = None;
    let mut events = 0;
    for (no, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let at = |e: String| format!("line {}: {e}: {raw}", no + 1);
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks[0] == "=>" {
            let p = pending
                .as_mut()
                .ok_or_else(|| at("=> without an event".into()))?;
            match toks.get(1).copied() {
                Some("none") => p.none = true,
                Some("error") => {
                    p.err = Some(match toks.get(2).copied() {
                        Some("event") => E_EVENT,
                        Some("full") => E_FULL,
                        Some("cap") => E_CAP,
                        Some("fault") => E_FAULT,
                        _ => return Err(at("unknown error".into())),
                    })
                }
                Some(s) => {
                    let rec = record(&toks[2..], vectors).map_err(at)?;
                    p.want.push(Record {
                        session: n32(s).map_err(at)?,
                        reserved: 0,
                        step: p.ev.step,
                        rec,
                    });
                }
                None => return Err(at("empty =>".into())),
            }
            continue;
        }
        if let Some(p) = pending.take() {
            check(oracle.as_mut().ok_or("no book")?, p)?;
        }
        let m = kv(&toks);
        let make = |o: &mut Option<Oracle>,
                    cfg: &Config,
                    a: &[Account],
                    s: &[Session]|
         -> Result<(), String> {
            if o.is_none() {
                *o = Some(Oracle::new(lib, cfg, a, s)?);
            }
            Ok(())
        };
        match toks[0] {
            "book" => {
                let band = get(&m, "band").map_err(at)?;
                let (lo, hi) = band
                    .split_once("..")
                    .ok_or_else(|| at("band=LO..HI".into()))?;
                cfg.band_lo = n32(lo).map_err(at)?;
                cfg.band_hi = n32(hi).map_err(at)?;
                for (k, f) in [
                    ("min_qty", &mut cfg.min_qty),
                    ("max_qty", &mut cfg.max_order_qty),
                    ("max_open", &mut cfg.max_open_per_acct),
                    ("max_orders", &mut cfg.max_orders),
                    ("max_fee_ppm", &mut cfg.max_fee_ppm),
                ] {
                    if let Some(v) = m.get(k) {
                        *f = n32(v).map_err(at)?;
                    }
                }
                if let Some(v) = m.get("qptl") {
                    cfg.quote_per_tick_lot = num(v).map_err(at)?;
                }
                if let Some(v) = m.get("phase") {
                    cfg.phase = phase(v).map_err(at)?;
                }
            }
            "lane" => {
                let l = usize::from(n8(toks.get(1).copied().unwrap_or_default()).map_err(at)?);
                if l >= 64 {
                    return Err(at("lane >= 64".into()));
                }
                if let Some(v) = m.get("rank") {
                    cfg.lane_rank[l] = n8(v).map_err(at)?;
                }
                if let Some(v) = m.get("first") {
                    cfg.lane_first_handle[l] = n32(v).map_err(at)?;
                }
            }
            "account" => accts.push(Account {
                id: n32(toks.get(1).copied().unwrap_or_default()).map_err(at)?,
                lane: n8(get(&m, "lane").map_err(at)?).map_err(at)?,
                maker_ppm: m.get("maker").map_or(Ok(0), |v| signed(v)).map_err(at)? as i32,
                taker_ppm: m.get("taker").map_or(Ok(0), |v| signed(v)).map_err(at)? as i32,
                auction_ppm: m.get("auction").map_or(Ok(0), |v| signed(v)).map_err(at)? as i32,
                base_free: m.get("base").map_or(Ok(0), |v| num(v)).map_err(at)?,
                quote_free: m.get("quote").map_or(Ok(0), |v| num(v)).map_err(at)?,
                ..Account::default()
            }),
            "session" => sess.push(Session {
                session: n32(toks.get(1).copied().unwrap_or_default()).map_err(at)?,
                account: n32(get(&m, "account").map_err(at)?).map_err(at)?,
            }),
            "msg" | "shed" | "step" | "phase" | "uncross" => {
                make(&mut oracle, &cfg, &accts, &sess)?;
                let mut ev = Event::default();
                if let Some(v) = m.get("step") {
                    ev.step = num(v).map_err(at)?;
                }
                match toks[0] {
                    "msg" | "shed" => {
                        // msg LANE SESSION INDEX [rx=] [seq=] [step=] : op ...
                        let colon = toks
                            .iter()
                            .position(|t| *t == ":")
                            .ok_or_else(|| at("missing :".into()))?;
                        ev.kind = if toks[0] == "msg" { 1 } else { 2 };
                        ev.arg = if toks[0] == "shed" { 6 } else { 0 };
                        ev.lane = n8(toks.get(1).copied().unwrap_or_default()).map_err(at)?;
                        ev.session = n32(toks.get(2).copied().unwrap_or_default()).map_err(at)?;
                        ev.index = n8(toks.get(3).copied().unwrap_or_default()).map_err(at)?;
                        ev.rx_ts = m.get("rx").map_or(Ok(0), |v| num(v)).map_err(at)?;
                        ev.lane_seq = m.get("seq").map_or(Ok(0), |v| num(v)).map_err(at)?;
                        ev.msg = msg(&toks[colon + 1..]).map_err(at)?;
                    }
                    "step" => {
                        ev.kind = 2;
                        ev.arg = match toks.get(1).copied() {
                            Some("cross") => 1,
                            Some("improve") => 2,
                            Some("rescan") => 3,
                            Some("depletion") => 4,
                            Some("idle") => 5,
                            Some("seal") => 8,
                            Some(k) => n8(k).map_err(at)?,
                            None => return Err(at("missing step kind".into())),
                        };
                    }
                    "phase" => {
                        ev.kind = 3;
                        ev.arg = phase(toks.get(1).copied().unwrap_or_default()).map_err(at)?;
                    }
                    _ => {
                        ev.kind = 4;
                        let r = n32(toks.get(1).copied().unwrap_or_default()).map_err(at)?;
                        ev.msg[..4].copy_from_slice(&r.to_le_bytes());
                    }
                }
                if let Some(v) = m.get("reserved") {
                    ev.reserved = n32(v).map_err(at)?; // to test malformed events
                }
                events += 1;
                pending = Some(Pending {
                    line: no + 1,
                    ev,
                    want: Vec::new(),
                    err: None,
                    none: false,
                });
            }
            "check" => {
                make(&mut oracle, &cfg, &accts, &sess)?;
                let st =
                    State::parse(&oracle.as_ref().ok_or("no book")?.state_bytes()).map_err(at)?;
                st.check(&toks[1..]).map_err(at)?;
            }
            "new_fails" => {
                if Oracle::new(lib, &cfg, &accts, &sess).is_ok() {
                    return Err(at("pbo_new accepted the config".into()));
                }
            }
            _ => return Err(at("unknown line".into())),
        }
    }
    if let Some(p) = pending.take() {
        check(oracle.as_mut().ok_or("no book")?, p)?;
    }
    Ok(events)
}

/// Compares one event's records with the expected ones, session by session in order.
fn check(o: &mut Oracle, p: Pending) -> Result<(), String> {
    let at = |e: String| format!("event at line {}: {e}", p.line);
    if p.want.is_empty() && p.err.is_none() && !p.none {
        return Err(at("no => line".into()));
    }
    let got = o.apply(&p.ev);
    let got = match (got, p.err) {
        (Err(c), Some(w)) if c == w => return Ok(()),
        (Ok(_), Some(w)) => return Err(at(format!("expected error {w:#x}"))),
        (Err(c), _) => return Err(at(format!("pbo_apply returned {c:#x}"))),
        (Ok(g), None) => g,
    };
    let by_session = |v: &[Record]| {
        let mut m: BTreeMap<u32, Vec<Record>> = BTreeMap::new();
        for r in v {
            m.entry(r.session).or_default().push(*r);
        }
        m
    };
    let (g, w) = (by_session(&got), by_session(&p.want));
    if g != w {
        let show = |m: &BTreeMap<u32, Vec<Record>>| {
            m.values()
                .flatten()
                .map(|r| format!("\n  {:#010x} step {} {:02x?}", r.session, r.step, r.rec))
                .collect::<String>()
        };
        return Err(at(format!(
            "records differ\n got:{}\nwant:{}",
            show(&g),
            show(&w)
        )));
    }
    Ok(())
}

/// The parts of the canonical state bytes (pbv.h) that scenarios check.
struct State {
    phase: u8,
    resting: Vec<u32>,
    lanes: Vec<u8>,
    last_step: u64,
    accounts: BTreeMap<u32, [u64; 6]>,
    fee_acc: Vec<i64>,
}

impl State {
    fn parse(b: &[u8]) -> Result<Self, String> {
        let u32_at = |o: usize| {
            b.get(o..o + 4)
                .map(|s| u32::from_le_bytes(s.try_into().unwrap_or_default()))
        };
        let u64_at = |o: usize| {
            b.get(o..o + 8)
                .map(|s| u64::from_le_bytes(s.try_into().unwrap_or_default()))
        };
        if u32_at(0) != Some(0x3153_4250) {
            return Err("state bytes: bad magic".into());
        }
        let n = u32_at(24).ok_or("short state")? as usize;
        let na = u32_at(28).ok_or("short state")? as usize;
        if b.len() != 32 + 48 * (n + na) + 512 {
            return Err(format!(
                "state bytes: {} bytes for {n} orders and {na} accounts",
                b.len()
            ));
        }
        let lanes = (0..n)
            .map(|i| b.get(32 + 48 * i + 13).copied().unwrap_or_default())
            .collect();
        let resting = (0..n)
            .map(|i| u32_at(32 + 48 * i).unwrap_or_default())
            .collect();
        let base = 32 + 48 * n;
        let mut accounts = BTreeMap::new();
        for i in 0..na {
            let o = base + 48 * i;
            let f = |k: usize| u64_at(o + k).unwrap_or_default();
            accounts.insert(
                u32_at(o).unwrap_or_default(),
                [
                    u64::from(u32_at(o + 4).unwrap_or_default()),
                    f(8),
                    f(16),
                    f(24),
                    f(32),
                    f(40),
                ],
            );
        }
        let fb = base + 48 * na;
        let fee_acc = (0..64)
            .map(|l| u64_at(fb + 8 * l).unwrap_or_default() as i64)
            .collect();
        Ok(Self {
            phase: b[6],
            resting,
            lanes,
            last_step: u64_at(16).unwrap_or_default(),
            accounts,
            fee_acc,
        })
    }

    fn check(&self, toks: &[&str]) -> Result<(), String> {
        match toks.first().copied() {
            Some("phase") => {
                let want = phase(toks.get(1).copied().unwrap_or_default())?;
                if self.phase != want {
                    return Err(format!("phase is {}", self.phase));
                }
            }
            Some("resting") => {
                let want = toks[1..]
                    .iter()
                    .map(|t| n32(t))
                    .collect::<Result<Vec<_>, _>>()?;
                if self.resting != want {
                    return Err(format!("resting is {:#010x?}", self.resting));
                }
            }
            Some("last_step") => {
                let want = num(toks.get(1).copied().unwrap_or_default())?;
                if self.last_step != want {
                    return Err(format!("last_step is {}", self.last_step));
                }
            }
            Some("lane") => {
                let h = n32(toks.get(1).copied().unwrap_or_default())?;
                let want = n8(toks.get(2).copied().unwrap_or_default())?;
                let i = self
                    .resting
                    .iter()
                    .position(|r| *r == h)
                    .ok_or(format!("{h:#x} is not resting"))?;
                if self.lanes[i] != want {
                    return Err(format!("{h:#x} has lane {}", self.lanes[i]));
                }
            }
            Some("fee_acc") => {
                let l = usize::from(n8(toks.get(1).copied().unwrap_or_default())?);
                let want = signed(toks.get(2).copied().unwrap_or_default())?;
                let have = self.fee_acc.get(l).copied().unwrap_or_default();
                if have != want {
                    return Err(format!("fee_acc[{l}] is {have}"));
                }
            }
            Some("account") => {
                let id = n32(toks.get(1).copied().unwrap_or_default())?;
                let a = self.accounts.get(&id).ok_or(format!("no account {id}"))?;
                let names = ["open", "base_free", "base_resv", "quote_free", "quote_resv"];
                for (k, v) in kv(&toks[2..]) {
                    let i = names
                        .iter()
                        .position(|n| *n == k)
                        .ok_or(format!("unknown field {k}"))?;
                    if a[i] != num(v)? {
                        return Err(format!("account {id} {k} is {}", a[i]));
                    }
                }
            }
            _ => return Err("unknown check".into()),
        }
        Ok(())
    }
}
