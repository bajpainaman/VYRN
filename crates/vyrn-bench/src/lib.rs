//! Benchmark harness: generator, echo server, microbenchmarks, histograms, report signing.
//!
//! This crate holds the workload generator (`generator`, `config`, `stream`, the PRNGs in `rng` and the
//! integer math in `fixed`) and the latency-histogram export (`hist`). The formats are specified
//! in `bench/workloads/FORMAT.md`.
#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]

pub mod config;
pub mod fixed;
pub mod generator;
pub mod hist;
pub mod rng;
pub mod stream;
