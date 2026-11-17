//! Config check, deploy, keys, epoch control, trace dump, release verify.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use vyrn_types as _;

mod release;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Release bundles (spec/11-build.md §9.5).
    #[command(subcommand)]
    Release(Release),
}

#[derive(Subcommand)]
enum Release {
    /// Check a bundle's signatures and every file hash (deploy/release/MANIFEST.md).
    Verify(Verify),
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Trust {
    /// Trusted release keys (TOML, `[[key]] id, ed25519`); 2 must have signed.
    #[arg(long, value_name = "FILE")]
    keys: Option<PathBuf>,
    /// Check hashes only and report the bundle as unsigned (CI and DEV; boxes never accept it).
    #[arg(long)]
    unsigned: bool,
}

#[derive(Args)]
struct Verify {
    /// The bundle: a directory holding manifest.toml, its files and signatures.
    dir: PathBuf,
    #[command(flatten)]
    trust: Trust,
}

fn main() -> ExitCode {
    let Command::Release(Release::Verify(args)) = Cli::parse().command;
    match release::verify(&args.dir, args.trust.keys.as_deref()) {
        Ok(v) => {
            let signed = if v.signers.is_empty() {
                "UNSIGNED".to_owned()
            } else {
                format!("signed by {}", v.signers.join(", "))
            };
            println!(
                "verified {} at {}: {} files, {signed}",
                v.tag, v.commit, v.files
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("release verify: {e}");
            ExitCode::FAILURE
        }
    }
}
