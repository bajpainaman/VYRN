//! `--dropcopy` (10 §8): the observer replica's drop copy, end to end. An observer
//! (`vyrn-validator`, `role = "observer"`) replays the box's blocks into its output ring,
//! `vyrn-dropcopy` serves the ring over Noise, and one client per session logs in to its
//! account's stream. The check compares what the clients received with an in-process
//! `DropCopy` over the tap's own `RustReplay`, and reconciles each record that carries a
//! `resp_seq` with the client's response packet (10 §8.3), which gives the DEV timing (R9).

use std::io::{Read as _, Write as _};
use std::net::{SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use vyrn_md::dropcopy::noise::NoiseStream;
use vyrn_md::dropcopy::wire::{FRAME_BYTES, Frame, FrameKind, Login};
use vyrn_md::dropcopy::{DcAccount, DcConfig, DcRecord, DcType, StreamId};
use vyrn_types::{AccountId, BookId, SessionId};

use crate::{BOOK, Sess, hex};

/// The server's Noise static secret (DEV).
const NOISE_SEED: [u8; 32] = [0x5a; 32];

/// The drop-copy account of the harness's `i`-th session: one account per session.
pub fn account(i: usize) -> AccountId {
    AccountId(100 + u32::try_from(i).unwrap_or(0))
}

fn seed(i: usize) -> [u8; 32] {
    [0x30u8.wrapping_add(u8::try_from(i).unwrap_or(0)); 32]
}

/// The accounts as `vyrn-dropcopy`'s config names them: no fees (the box charges none).
pub fn dc_config(sessions: &[Sess]) -> DcConfig {
    DcConfig {
        book: BookId(BOOK),
        tick_size: 1,
        accounts: sessions
            .iter()
            .enumerate()
            .map(|(i, s)| DcAccount {
                account: account(i),
                master: None,
                sessions: vec![s.id],
                taker_ppm: 0,
                maker_ppm: 0,
                msg_fee_improve: 0,
                msg_fee_cross: 0,
            })
            .collect(),
    }
}

/// `vyrn-dropcopy`'s config and Noise key file under `dir`.
pub fn server_config(
    dir: &Path,
    listen: SocketAddrV4,
    sessions: &[Sess],
) -> Result<PathBuf, String> {
    let key = dir.join("dropcopy.noise");
    std::fs::write(&key, hex(&NOISE_SEED)).map_err(|e| e.to_string())?;
    let mut s = format!(
        "book = {BOOK}\nlisten = \"{listen}\"\nnoise_key_file = \"{}\"\ntick_size = 1\n",
        key.display()
    );
    for (i, x) in sessions.iter().enumerate() {
        s.push_str(&format!(
            "\n[[account]]\nid = {}\nkey = \"{}\"\nsessions = [{}]\n",
            account(i).0,
            hex(&vyrn_crypto::ed25519::public_key(&seed(i))),
            x.id.0
        ));
    }
    let p = dir.join("dropcopy.toml");
    std::fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(p)
}

/// The frames one client received, with their receive times.
pub type Got = Arc<Mutex<Vec<(Instant, Frame)>>>;

fn lock(g: &Got) -> std::sync::MutexGuard<'_, Vec<(Instant, Frame)>> {
    g.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Logs in to account `i`'s own stream at `addr` from seq 1 and reads until `stop`. Retries
/// until `deadline` while the server is not up or rejects (its ring not begun yet).
pub fn client(
    addr: SocketAddrV4,
    i: usize,
    stop: Arc<AtomicBool>,
    deadline: Instant,
) -> (Got, std::thread::JoinHandle<Result<(), String>>) {
    let got: Got = Arc::default();
    let g = Arc::clone(&got);
    let h = std::thread::spawn(move || {
        let spub = vyrn_crypto::x25519::public_key(&NOISE_SEED);
        let eph = [0x60u8.wrapping_add(u8::try_from(i).unwrap_or(0)); 32];
        let retry = || {
            if Instant::now() > deadline {
                return Err(format!("drop-copy client {i}: no session by the deadline"));
            }
            std::thread::park_timeout(Duration::from_millis(20));
            Ok(())
        };
        let mut c = loop {
            let Ok(tcp) = TcpStream::connect(addr) else {
                retry()?;
                continue;
            };
            let _ = tcp.set_nodelay(true);
            tcp.set_read_timeout(Some(Duration::from_secs(2)))
                .map_err(|e| e.to_string())?;
            let mut c = NoiseStream::connect(tcp, BookId(BOOK), &spub, &eph)
                .map_err(|e| format!("drop-copy client {i}: noise: {e}"))?;
            let mut f = [0u8; FRAME_BYTES];
            c.read_exact(&mut f).map_err(|e| e.to_string())?;
            let hello = Frame::decode(&f).ok_or("bad HELLO")?;
            let mut challenge = [0u8; 32];
            challenge.copy_from_slice(&hello.body[..32]);
            let login = Login {
                master: false,
                book: BookId(BOOK),
                account: account(i),
                epoch: hello.epoch,
                from: 1,
                signer: account(i),
                challenge,
            };
            c.write_all(&login.encode_signed(&seed(i)))
                .map_err(|e| e.to_string())?;
            c.read_exact(&mut f).map_err(|e| e.to_string())?;
            match Frame::decode(&f).map(|f| f.kind) {
                Some(FrameKind::Accept) => break c,
                _ => retry()?,
            }
        };
        c.get_mut()
            .set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|e| e.to_string())?;
        // Transport message boundaries mean nothing (10 §8.5 item 5): frames are cut here.
        let (mut buf, mut tmp) = (Vec::new(), [0u8; 4096]);
        while !stop.load(Ordering::Acquire) {
            match c.read(&mut tmp) {
                Ok(0) => return Err(format!("drop-copy client {i}: server closed")),
                Ok(n) => {
                    let t = Instant::now();
                    buf.extend_from_slice(tmp.get(..n).unwrap_or_default());
                    let whole = buf.len() / FRAME_BYTES * FRAME_BYTES;
                    let mut g = lock(&g);
                    for f in buf[..whole].as_chunks::<FRAME_BYTES>().0 {
                        g.push((t, Frame::decode(f).ok_or("bad frame")?));
                    }
                    buf.drain(..whole);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(format!("drop-copy client {i}: {e}")),
            }
        }
        Ok(())
    });
    (got, h)
}

/// A stage marker, not part of the canonical stream (10 §8.4 item 3).
fn marker(r: &DcRecord) -> bool {
    matches!(r.kind(), DcType::Final | DcType::Settled | DcType::Revert)
}

/// Every stream is drained (Codex on #154): a heartbeat received after `since`, which the caller
/// sets once the observer has stopped and the server has had time to apply its ring, reports
/// the stream's newest seq, every record up to it has arrived, and the last is a `DC_FINAL`
/// (10 §8.4 item 7). A lagging server or client therefore keeps the wait going instead of
/// passing an early prefix.
pub fn settled(got: &[Got], since: Instant) -> bool {
    got.iter().all(|g| {
        let g = lock(g);
        let last = g
            .iter()
            .rev()
            .find_map(|(_, f)| Some((f.seq, f.as_record()?)));
        let n = last.map_or(0, |(q, _)| q);
        let hb = g
            .iter()
            .rev()
            .find(|(t, f)| *t > since && f.kind == FrameKind::Heartbeat)
            .is_some_and(|(_, f)| f.seq == n);
        hb && last.is_none_or(|(_, r)| r.kind() == DcType::Final)
    })
}

/// The `dropcopy` check (module docs). `responses`: when the client received each response
/// packet, by `(session, resp_seq)`; `inproc`: the in-process `DropCopy`'s records.
pub fn check(
    got: &[Got],
    responses: &[(Instant, u32, u32)],
    inproc: &[(StreamId, u64, DcRecord)],
    lost: &[(u32, u32)],
) -> Result<String, String> {
    let mut canonical = 0usize;
    let mut finals = 0usize;
    let mut lat_us: Vec<i64> = Vec::new();
    let mut fills = 0usize;
    let mut unseen = 0usize;
    for (i, g) in got.iter().enumerate() {
        let own = StreamId {
            account: account(i),
            master: false,
        };
        let frames = lock(g).clone();
        let mut recs: Vec<(Instant, u64, DcRecord)> = Vec::new();
        for (t, f) in frames.iter().filter(|(_, f)| f.kind == FrameKind::Record) {
            let r = f
                .as_record()
                .ok_or_else(|| format!("{own:?}: RECORD {} with a malformed body", f.seq))?;
            recs.push((*t, f.seq, r));
        }
        if let Some(k) = recs
            .iter()
            .zip(1u64..)
            .position(|((_, q, _), want)| *q != want)
        {
            return Err(format!("{own:?}: seq gap at record {k}"));
        }
        let served: Vec<&DcRecord> = recs.iter().map(|r| &r.2).filter(|r| !marker(r)).collect();
        let want: Vec<&DcRecord> = inproc
            .iter()
            .filter(|(s, _, r)| *s == own && !marker(r))
            .map(|(_, _, r)| r)
            .collect();
        if served != want {
            let at = served.iter().zip(&want).position(|(a, b)| a != b);
            return Err(format!(
                "{own:?}: served {} canonical records, in-process {}; first differs at {at:?}",
                served.len(),
                want.len()
            ));
        }
        let last_canon = recs.iter().rposition(|r| !marker(&r.2));
        let last_final = recs.iter().rposition(|r| r.2.kind() == DcType::Final);
        if last_canon.is_some() && last_final < last_canon {
            return Err(format!("{own:?}: records after its last DC_FINAL"));
        }
        canonical += served.len();
        finals += recs.iter().filter(|r| r.2.kind() == DcType::Final).count();
        // Online reconciliation (10 §8.3): a record with a resp_seq names the response packet
        // that carried its client record; makers' fills (resp_seq 0) reconcile by step instead
        // (10 §8.4 item 4), and stage markers and DC_EOD carry none.
        for (t, _, r) in &recs {
            if marker(r) || r.kind() == DcType::Eod || r.resp_seq() == 0 {
                continue;
            }
            fills += usize::from(r.kind() == DcType::Fill);
            let key = (r.session(), r.resp_seq());
            let Some((ct, _, _)) = responses
                .iter()
                .find(|(_, s, q)| (SessionId(*s), *q) == key)
            else {
                // R1: replay produced this response and the client's socket dropped it.
                if lost.contains(&(key.0.0, key.1)) {
                    unseen += 1;
                    continue;
                }
                return Err(format!(
                    "{own:?}: {:?} {key:?} has no response packet",
                    r.kind()
                ));
            };
            let d = if t >= ct {
                i64::try_from(t.duration_since(*ct).as_micros()).unwrap_or(i64::MAX)
            } else {
                -i64::try_from(ct.duration_since(*t).as_micros()).unwrap_or(i64::MAX)
            };
            lat_us.push(d);
        }
    }
    if lat_us.is_empty() {
        return Err(format!(
            "no record with a resp_seq reached a client ({canonical} canonical records)"
        ));
    }
    lat_us.sort_unstable();
    let pct = |p: usize| lat_us[(lat_us.len() - 1) * p / 100];
    Ok(format!(
        "{} streams, {canonical} canonical records equal the in-process DropCopy, {finals} DC_FINALs cover them; \
         each record with a resp_seq names a response packet the client got, or one replay produced \
         that the client's socket dropped (R1: {unseen}); \
         DEV (shared host, unpinned, per-block replay; not a latency result): record after its response packet \
         p50={}us p99={}us max={}us over {} records ({fills} DC_FILL) (REQ-LAT-12 on REF: p99 <= 50us)",
        got.len(),
        pct(50),
        pct(99),
        lat_us.last().copied().unwrap_or(0),
        lat_us.len()
    ))
}
