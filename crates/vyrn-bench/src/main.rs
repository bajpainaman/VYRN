//! The `vyrn-bench` binary: `gen` writes a workload stream, `hist` summarizes a histogram export.
#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use vyrn_bench::config::Config;
use vyrn_bench::generator::GenOptions;
use vyrn_bench::hist::LatencyHist;
use vyrn_bench::stream::write_stream;

#[derive(Parser)]
#[command(name = "vyrn-bench", version, about = "VYRN benchmark harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Turn a workload config and a seed into a stream of request packets (VYRN-GEN v1).
    Gen(GenArgs),
    /// Print percentiles of a VYRN-HIST export.
    Hist(HistArgs),
}

#[derive(Args)]
struct GenArgs {
    /// Workload config, such as bench/workloads/wl-ref.toml.
    #[arg(long)]
    config: PathBuf,
    /// run_seed, decimal or 0x-hex.
    #[arg(long, value_parser = parse_seed)]
    seed: u64,
    /// Stop after this many packets (default: the config's whole duration).
    #[arg(long)]
    packets: Option<u64>,
    /// Replace the config's rate_msgs_per_s.
    #[arg(long)]
    rate: Option<u64>,
    /// Output file (default: stdout).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Print the BLAKE3 of the stream and the message counts to stderr.
    #[arg(long)]
    stats: bool,
}

#[derive(Args)]
struct HistArgs {
    file: PathBuf,
}

fn parse_seed(s: &str) -> Result<u64, String> {
    let r = match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    };
    r.map_err(|e| format!("bad seed {s:?}: {e}"))
}

/// Hashes what passes through it.
struct Tee<W> {
    inner: W,
    hasher: blake3::Hasher,
}

impl<W: Write> Write for Tee<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(buf.get(..n).unwrap_or_default());
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn gen_cmd(a: GenArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::parse(&std::fs::read_to_string(&a.config)?)?;
    let opts = GenOptions {
        seed: a.seed,
        rate_override: a.rate,
    };
    let sink: Box<dyn Write> = match &a.out {
        Some(p) => Box::new(File::create(p)?),
        None => Box::new(io::stdout().lock()),
    };
    let mut out = Tee {
        inner: BufWriter::new(sink),
        hasher: blake3::Hasher::new(),
    };
    let stats = write_stream(&cfg, &opts, a.packets, &mut out)?;
    out.flush()?;
    if a.stats {
        let hex = out
            .hasher
            .finalize()
            .as_bytes()
            .iter()
            .fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
        eprintln!("blake3 {hex}\n{stats}");
    }
    Ok(())
}

fn hist_cmd(a: HistArgs) -> Result<(), Box<dyn std::error::Error>> {
    let (name, h) = LatencyHist::parse(&std::fs::read_to_string(&a.file)?)?;
    println!("name {name}\ncount {}", h.count());
    for (label, q) in [
        ("p50", 500_000),
        ("p90", 900_000),
        ("p99", 990_000),
        ("p99.9", 999_000),
        ("p99.99", 999_900),
    ] {
        if let Some(v) = h.value_at_ppm(q) {
            println!("{label} {v} ns");
        }
    }
    if let Some(m) = h.max() {
        println!(
            "max {} ns (session {} pkt_seq {} index {})",
            m.value_ns, m.req.session, m.req.pkt_seq, m.req.index
        );
    }
    println!("overflow {}", h.overflow().len());
    Ok(())
}

fn main() -> ExitCode {
    let r = match Cli::parse().cmd {
        Cmd::Gen(a) => gen_cmd(a),
        Cmd::Hist(a) => hist_cmd(a),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vyrn-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
