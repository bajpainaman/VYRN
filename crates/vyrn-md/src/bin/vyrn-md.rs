//! The `vyrn-md` binary: encodes every feed of one book and publishes it (10 §7.7).
//!
//! Until the observer replica implements `ReplayStream`, the input is an event script in the
//! format of `tests/mbo_vectors.txt` (`--events`). Output goes through `vyrn-nic` (`kernel_udp`
//! backend) either to one multicast group per feed channel (`--mcast-base`) or to unicast
//! destinations with the relay rotation of 10 §7.7 (`--unicast`, repeatable). `--retx` serves
//! the retransmit service on TCP after publishing, until killed.
//!
//! Multicast group of a channel: `mcast_base + (feed << 4 | index)`, port `--port`.
//! \[Guessing\] 10 §7.7 fixes one group per channel per feed but not the numbering.
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::process::ExitCode;

use clap::Parser;
use vyrn_md::{
    BookOp, Channel, DeleteCause, Event, EventKind, LevelEncoder, MD_MBO_W_TICKS, MD_RETX_SECS,
    MboEncoder, MboWEncoder, PacketSink, RetxStore, Side, StatsEncoder, TradesEncoder, WithMboC,
};
use vyrn_nic::frame::{self, Endpoint, FrameHdr, MAX_FRAME_BYTES};
use vyrn_nic::{BackendKind, KernelUdp, NicBackend, NicConfig, PortConfig, PortId, TxClass};
use vyrn_types::{BookId, Epoch, Nanos, Qty, StepId, StepKind, Tick};
use vyrn_wire::TxRing;

#[derive(Parser)]
#[command(about = "Market data publisher (spec 10 §7)")]
struct Args {
    /// Event script (tests/mbo_vectors.txt format).
    #[arg(long)]
    events: std::path::PathBuf,
    /// Local address to send from.
    #[arg(long, default_value = "0.0.0.0")]
    src: Ipv4Addr,
    /// Multicast base group; one group per feed channel.
    #[arg(long, conflicts_with = "unicast")]
    mcast_base: Option<Ipv4Addr>,
    /// UDP port of every multicast group.
    #[arg(long, default_value_t = 31_000)]
    port: u16,
    /// Unicast destination (ip:port), repeatable; every destination gets every packet.
    #[arg(long)]
    unicast: Vec<SocketAddrV4>,
    /// Serve the retransmit service on this TCP address after publishing.
    #[arg(long)]
    retx: Option<SocketAddrV4>,
}

/// Sends each packet as a fast-path frame, and stores it for retransmit.
struct Publisher<T: TxRing> {
    tx: T,
    src: Ipv4Addr,
    mcast: Option<(Ipv4Addr, u16)>,
    unicast: Vec<SocketAddrV4>,
    sent: u64,
    frame: Vec<u8>,
    retx: RetxStore,
    errors: u64,
}

impl<T: TxRing> Publisher<T> {
    fn send(&mut self, dst: SocketAddrV4, payload: &[u8]) {
        let hdr = FrameHdr {
            src: Endpoint {
                mac: [0; 6],
                ip: self.src,
                port: 0,
            },
            dst: Endpoint {
                mac: [0; 6],
                ip: *dst.ip(),
                port: dst.port(),
            },
        };
        let Ok(n) = frame::build(&hdr, payload, &mut self.frame) else {
            self.errors += 1;
            return;
        };
        while self.tx.send(&self.frame[..n]).is_err() {
            self.tx.reap();
        }
    }
}

impl<T: TxRing> PacketSink for Publisher<T> {
    fn emit(&mut self, channel: Channel, bytes: &[u8]) {
        self.retx.store(bytes);
        if let Some((base, port)) = self.mcast {
            let off = (u32::from(channel.feed.code()) << 4) | u32::from(channel.index);
            let group = Ipv4Addr::from(u32::from(base).wrapping_add(off));
            self.send(SocketAddrV4::new(group, port), bytes);
        }
        // Subscriber i of n gets packet s in position (i + s) mod n (10 §7.7).
        let n = self.unicast.len() as u64;
        for pos in 0..n {
            let i = (pos + n - self.sent % n) % n;
            let dst = self.unicast[usize::try_from(i).unwrap_or(0)];
            self.send(dst, bytes);
        }
        self.sent += 1;
    }
}

fn num(s: &str) -> Result<u64, String> {
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    }
    .map_err(|e| format!("{s}: {e}"))
}

fn op(w: &[&str]) -> Result<BookOp, String> {
    let u = |i: usize| -> Result<u32, String> {
        let v = num(w.get(i).ok_or("short line")?)?;
        u32::try_from(v).map_err(|e| e.to_string())
    };
    let side = |i| u(i).map(|v| if v == 0 { Side::Buy } else { Side::Sell });
    Ok(match w.first().copied() {
        Some("add") => BookOp::Add {
            oid: u(1)?,
            side: side(2)?,
            tick: Tick(u(3)?),
            qty: Qty(u(4)?),
            prio_ts: Nanos(u64::from(u(5)?)),
            via_bbo: u(6)? == 1,
            auction: u(7)? == 1,
        },
        Some("del") => BookOp::Delete {
            oid: u(1)?,
            cause: u8::try_from(u(2)?)
                .ok()
                .and_then(DeleteCause::from_code)
                .ok_or("bad cause")?,
            tick: Tick(u(3)?),
            qty: Qty(u(4)?),
        },
        Some("reduce") => BookOp::Reduce {
            oid: u(1)?,
            tick: Tick(u(2)?),
            qty_after: Qty(u(3)?),
        },
        k => return Err(format!("op {k:?}")),
    })
}

/// Parses the event script: (book, epoch, events).
fn parse(text: &str) -> Result<(BookId, Epoch, Vec<Event>), String> {
    let (mut book, mut epoch, mut events) = (0, 0, vec![]);
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let w: Vec<&str> = line.split(' ').collect();
        let arg = |i: usize| num(w.get(i).ok_or("short line")?);
        match w[0] {
            "book" => book = arg(1)?,
            "epoch" => epoch = arg(1)?,
            "ev" => {
                let a = &w[2..];
                let n = |i: usize| num(a.get(i).ok_or("short line")?);
                let kind = match a.first().copied() {
                    Some("lane") => EventKind::LaneOp(op(&a[1..])?),
                    Some("stepop") => EventKind::StepOp(op(&a[1..])?),
                    Some("step") => EventKind::Step {
                        step: StepId(n(1)?),
                        kind: u8::try_from(n(2)?)
                            .ok()
                            .and_then(StepKind::from_code)
                            .ok_or("bad step kind")?,
                        n_exec: u16::try_from(n(3)?).map_err(|e| e.to_string())?,
                        taker: u32::try_from(n(4)?).map_err(|e| e.to_string())?,
                    },
                    Some("exec") => EventKind::Exec {
                        aggressor: if n(1)? == 0 { Side::Buy } else { Side::Sell },
                        ordinal: u16::try_from(n(2)?).map_err(|e| e.to_string())?,
                        maker: u32::try_from(n(3)?).map_err(|e| e.to_string())?,
                        tick: Tick(u32::try_from(n(4)?).map_err(|e| e.to_string())?),
                        qty: Qty(u32::try_from(n(5)?).map_err(|e| e.to_string())?),
                    },
                    Some("tick") => EventKind::TimerTick,
                    k => return Err(format!("event {k:?}")),
                };
                events.push(Event {
                    rx_ts: Nanos(arg(1)?),
                    kind,
                });
            }
            // Vector expectations, not input.
            "end" | "pkt" | "order" => {}
            k => return Err(format!("line {k}")),
        }
    }
    let book = BookId(u16::try_from(book).map_err(|e| e.to_string())?);
    let epoch = Epoch(u32::try_from(epoch).map_err(|e| e.to_string())?);
    Ok((book, epoch, events))
}

fn run(args: &Args) -> Result<(), String> {
    let text = std::fs::read_to_string(&args.events).map_err(|e| e.to_string())?;
    let (book, epoch, events) = parse(&text)?;
    let cfg = NicConfig::new(
        BackendKind::Kernel,
        vec![PortConfig {
            id: PortId(0),
            ip: args.src,
        }],
    );
    let mut nic = KernelUdp::open(&cfg).map_err(|e| e.to_string())?;
    let tx = nic
        .tx_ring(PortId(0), TxClass::Control)
        .map_err(|e| e.to_string())?;
    let mut publisher = Publisher {
        tx,
        src: args.src,
        mcast: args.mcast_base.map(|b| (b, args.port)),
        unicast: args.unicast.clone(),
        sent: 0,
        frame: vec![0; MAX_FRAME_BYTES],
        retx: RetxStore::new(MD_RETX_SECS * 1_000_000_000),
        errors: 0,
    };
    let start = events.first().map_or(Nanos(0), |e| e.rx_ts);
    let e = |x| format!("{x:?}");
    // One pass per feed: each encoder is a pure function of the same stream.
    let mut sink = WithMboC::new(publisher);
    MboEncoder::new(book, epoch)
        .run(&mut events.iter().copied(), &mut sink)
        .map_err(e)?;
    publisher = sink.inner;
    LevelEncoder::mbp10(book, epoch)
        .run(&mut events.iter().copied(), &mut publisher)
        .map_err(e)?;
    LevelEncoder::tob(book, epoch)
        .run(&mut events.iter().copied(), &mut publisher)
        .map_err(e)?;
    TradesEncoder::new(book, epoch)
        .run(&mut events.iter().copied(), &mut publisher)
        .map_err(e)?;
    StatsEncoder::new(book, epoch, start)
        .run(&mut events.iter().copied(), &mut publisher)
        .map_err(e)?;
    MboWEncoder::new(book, epoch, MD_MBO_W_TICKS)
        .run(&mut events.iter().copied(), &mut publisher)
        .map_err(e)?;
    tracing::info!(
        packets = publisher.sent,
        errors = publisher.errors,
        "published"
    );
    if let Some(addr) = args.retx {
        let l = TcpListener::bind(addr).map_err(|e| e.to_string())?;
        tracing::info!(%addr, "retransmit service");
        for conn in l.incoming() {
            let Ok(mut c) = conn else { continue };
            if let Err(err) = publisher.retx.serve(&mut c) {
                tracing::warn!(%err, "retransmit connection");
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vyrn-md: {e}");
            ExitCode::FAILURE
        }
    }
}
