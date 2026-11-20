//! The standby's side of sequencer failover (07 §9.5), DEV.
//!
//! A box with `[standby]` is `seq_order[j]`, `j ≥ 1`. Before its engine starts it:
//!
//! 1. joins the voters' commonware-p2p network as a non-voting peer authenticated by its
//!    `seq_key` (`vyrn_consensus::net::start_standby`), heard on the tail channel only;
//! 2. sends, every 50 ms, a signed `Silence` whose TailReport is reporter `n + j`, promotable,
//!    `replay_lag_us = 0`, with empty tails. *Reading* (**semantics**): 07 §9.5 has the standby
//!    report when it learns of the silence; it holds no frames here, so its report says only
//!    that it is promotable, and voters count it toward `next_seq`, never toward Q or the prefix;
//! 3. waits for a verified kind-1 certificate (its finality listener) whose `REP_SealExt`
//!    `next_seq` is `j`, and for the seal header itself, which voters send it on the tail
//!    channel. *Reading* (**wire**): the certificate carries `last_hash` but not the header's
//!    `last_step`, which the next `TenureStart` needs; the header is accepted only when its hash
//!    is the certificate's `last_hash`.
//!
//! Then `main.rs` opens tenure `next_tenure` above the seal: `first_height = H_s + 1`,
//! `first_step = last_step + 1`, `prev_header_hash = header_hash(seal)`. *DEV gap*: the engine
//! starts from `[engine]` and `[[dev_session]]`, not from the prefix (07 §9.5 replays it), so
//! the replicas' replay stops at the seal; its step ids are offset by the seal's `last_step` in
//! the log (`StreamCore::step_base`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use commonware_runtime::{Runner as _, Supervisor as _};
use vyrn_consensus::FinalityCert;
use vyrn_consensus::net::{self, Peer};
use vyrn_consensus::silence::Reason;
use vyrn_consensus::tail::{Silence, Tail, TailReport};
use vyrn_log::block::{HEADER_BYTES, decode_header, header_hash};
use vyrn_types::{BlockHeader, Epoch, Height, HomeCode};

use crate::config::{Consensus, Standby};

/// What a finalized seal hands the standby: the seal header its tenure starts on, the tenure,
/// and its own index in `seq_order` (the frames' `sender`).
pub struct Promotion {
    pub header: BlockHeader,
    pub tenure: u8,
    pub sender: u8,
}

fn sock(a: vyrn_epoch::Addr) -> SocketAddr {
    let ip = std::net::Ipv6Addr::from(a.ip);
    match ip.to_ipv4_mapped() {
        Some(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), a.port),
        None => SocketAddr::new(std::net::IpAddr::V6(ip), a.port),
    }
}

/// Waits as the standby until a seal names it (module docs); `None` once `stop` is set.
pub fn wait(
    c: &Consensus,
    s: &Standby,
    home: HomeCode,
    epoch: Epoch,
    seed: [u8; 32],
    seals: &Receiver<FinalityCert>,
    stop: &AtomicBool,
) -> Result<Option<Promotion>, String> {
    let (m, roster) = crate::finality::membership(c, home, epoch)?;
    let me = vyrn_crypto::ed25519::public_key(&seed);
    let j = m
        .seq()
        .iter()
        .position(|b| b.seq_key == me)
        .filter(|&j| j >= 1)
        .ok_or("[standby]: keys.seq is not a standby seq_key of the roster's seq_order")?;
    let key = |k: &[u8]| <[u8; 32]>::try_from(k).map_err(|_| "a roster key is not 32 bytes");
    let peers = roster
        .home(home)
        .voters
        .iter()
        .map(|v| {
            Ok(Peer {
                vote_key: key(&v.vote_key)?,
                node_key: key(&v.node_key)?,
                repl_addr: sock(v.repl_addr),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let n = m.committee().n();
    let reporter = u8::try_from(n + j).map_err(|e| e.to_string())?;
    let sender = u8::try_from(j).map_err(|e| e.to_string())?;
    let report = TailReport {
        epoch,
        tenure: 0,
        reporter,
        held_height: Height(0),
        tails: [Tail::default(), Tail::default()],
        t_last_rx: 0,
        replay_lag_us: 0,
        promotable: true,
    };
    let silence = Silence::sign(0, Reason::Silence, report, &seed).encode();
    let (hdr_tx, hdr_rx) = std::sync::mpsc::channel::<[u8; HEADER_BYTES]>();
    let done = Arc::new(AtomicBool::new(false));
    let listen = s.repl;
    let p2p = {
        let done = Arc::clone(&done);
        std::thread::Builder::new()
            .name("vyrn-seq/standby".into())
            .spawn(move || {
                commonware_runtime::tokio::Runner::new(commonware_runtime::tokio::Config::new())
                    .start(|ctx| async move {
                        let mut tail = net::start_standby(ctx.child("net"), seed, listen, &peers)
                            .map_err(|e| {
                            eprintln!("vyrn-seq: standby p2p: {e}");
                            e.to_string()
                        })?;
                        let mut tick = tokio::time::interval(Duration::from_millis(50));
                        while !done.load(Ordering::Acquire) {
                            tokio::select! {
                                Some((_, b)) = tail.recv() => {
                                    if let Ok(h) = <[u8; HEADER_BYTES]>::try_from(b.as_slice()) {
                                        let _ = hdr_tx.send(h);
                                    }
                                }
                                _ = tick.tick() => tail.broadcast(silence.clone()),
                            }
                        }
                        Ok::<(), String>(())
                    })
            })
            .map_err(|e| e.to_string())?
    };
    println!("STANDBY seq_index={j} repl={listen}");
    let mut want: Option<(Height, vyrn_types::Hash, u8)> = None;
    let mut held: Vec<BlockHeader> = Vec::new();
    let out = loop {
        if stop.load(Ordering::Acquire) {
            break None;
        }
        while let Ok(cert) = seals.try_recv() {
            if let Some(x) = cert.seal.as_ref()
                && usize::from(x.next_seq) == j
            {
                println!(
                    "SEAL_FINAL height={} next_seq={} next_tenure={}",
                    cert.proposal.last_height.0, x.next_seq, x.next_tenure
                );
                want = Some((
                    cert.proposal.last_height,
                    cert.proposal.last_hash,
                    x.next_tenure,
                ));
            }
        }
        while let Ok(b) = hdr_rx.try_recv() {
            held.push(decode_header(&b));
        }
        if let Some((height, hash, tenure)) = want
            && let Some(h) = held
                .iter()
                .find(|h| h.height == height && header_hash(h) == hash)
        {
            break Some(Promotion {
                header: *h,
                tenure,
                sender,
            });
        }
        std::thread::park_timeout(Duration::from_millis(1));
    };
    done.store(true, Ordering::Release);
    match p2p.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("standby p2p: {e}")),
        Err(_) => return Err("standby p2p thread panicked".into()),
    }
    Ok(out)
}
