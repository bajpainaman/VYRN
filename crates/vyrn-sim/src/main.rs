//! The `vyrn-sim` binary (11 §6.4 "Replaying and shrinking").
//!
//! - `vyrn-sim run --seed <hex> [--faults '<schedule>'] [--tail <n>]` runs one seed, with its
//!   generated schedule or the given one, and prints the report: seed, configuration, schedule,
//!   trace hash, counts, then `PASS` or `FAIL <check> at event <i>: <detail>` and the last `n`
//!   events (default 50, at most 10,000). Exit status 0 on pass, 1 on a failed check.
//! - `vyrn-sim shrink --seed <hex> [--faults '<schedule>']` removes faults one at a time while
//!   the same check still fails and prints the smallest schedule as a `run` command line.
//!
//! The schedule text format is `vyrn_sim::cluster::Schedule`'s. Seeds are hexadecimal, with or
//! without `0x`.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vyrn_sim::cluster::{self, Report, Schedule};

#[derive(Parser)]
#[command(about = "Deterministic whole-cluster simulator (spec/11-build.md §6.4)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run one seed.
    Run {
        #[arg(long, value_parser = parse_seed)]
        seed: u64,
        /// A fault schedule; default: the seed's own.
        #[arg(long)]
        faults: Option<String>,
        /// Events to print on failure.
        #[arg(long, default_value_t = 50)]
        tail: usize,
    },
    /// Shrink a failing seed's schedule.
    Shrink {
        #[arg(long, value_parser = parse_seed)]
        seed: u64,
        #[arg(long)]
        faults: Option<String>,
    },
}

fn parse_seed(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn schedule(seed: u64, faults: Option<&str>) -> Result<Schedule, String> {
    match faults {
        Some(f) => Schedule::parse(f),
        None => Ok(Schedule::generate(seed, &cluster::Config::from_seed(seed))),
    }
}

fn print(r: &Report, tail: usize) {
    println!("seed     {:016x}", r.seed);
    println!("config   {:?}", r.config);
    println!("faults   {}", r.schedule.render());
    println!("trace    {}", r.trace_hex());
    println!("stats    {:?}", r.stats);
    match &r.violation {
        None => println!("PASS"),
        Some(v) => {
            println!("FAIL {} at event {}: {}", v.check, v.index, v.detail);
            let skip = r.tail.len().saturating_sub(tail);
            for l in r.tail.iter().skip(skip) {
                println!("  {l}");
            }
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.cmd {
        Cmd::Run { seed, faults, tail } => schedule(seed, faults.as_deref()).map(|s| {
            let r = cluster::run(seed, &s);
            print(&r, tail);
            r.violation.is_none()
        }),
        Cmd::Shrink { seed, faults } => {
            schedule(seed, faults.as_deref()).map(|s| match cluster::shrink(seed, &s) {
                None => {
                    println!("seed {seed:016x} passes; nothing to shrink");
                    true
                }
                Some(r) => {
                    print(&r, 20);
                    println!(
                        "repro    vyrn-sim run --seed {:016x} --faults '{}'",
                        r.seed,
                        r.schedule.render()
                    );
                    false
                }
            })
        }
    };
    match res {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("vyrn-sim: {e}");
            ExitCode::from(2)
        }
    }
}
