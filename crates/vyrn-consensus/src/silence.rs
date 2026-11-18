//! Sequencer-silence detection and the deposition count (spec/07-replication.md §9.1–9.2).
//!
//! A voter **suspects** the sequencer when no frame of the current tenure has arrived on either
//! path for `FAILOVER_SILENCE_MS` = 2 ms (07 §9.1). [`Frames`] is the one value the frame paths
//! touch: each path calls [`Frames::on_frame`] for every frame of the tenure, heartbeats included.
//! [`watch`] sleeps on the runtime clock until the newest frame is `FAILOVER_SILENCE_MS` old and
//! returns the [`Suspicion`]. It runs on the consensus thread under any `commonware-runtime`
//! (tokio in production, `deterministic` in tests).
//!
//! The other two suspicion reasons (equivocation evidence, an unrepairable `order_root`) come from
//! other components; they construct a [`Suspicion`] themselves. The signed `Silence` message and
//! its TailReport (07 §9.3) are [`crate::tail`]; [`Deposition`] counts the voters whose `Silence`
//! [`crate::tail::Silence::verify`] returned as [`crate::tail::Reporter::Voter`].

use commonware_runtime::Clock;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};
use vyrn_types::FAILOVER_SILENCE_MS;

/// `FAILOVER_SILENCE_MS` as a duration.
pub const SILENCE: Duration = Duration::from_millis(FAILOVER_SILENCE_MS);

/// `Silence.reason` (07 §9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// No frame for `FAILOVER_SILENCE_MS`.
    Silence,
    /// Valid equivocation evidence (07 §10.1).
    Equivocation,
    /// `order_root` failed after repair from every source, or `REP_E_HASHLAG`.
    RootMismatch,
}

/// One suspicion of the sequencer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suspicion {
    pub reason: Reason,
    /// When the newest frame of the tenure arrived (`t_last_rx` of the TailReport, 07 §9.3).
    pub last_rx: SystemTime,
    /// When the voter suspected.
    pub at: SystemTime,
}

/// Arrival time of the newest frame of the current tenure, shared by both frame paths.
#[derive(Clone, Debug)]
pub struct Frames(Arc<Mutex<SystemTime>>);

impl Frames {
    /// Starts the silence clock at `now` (tenure start).
    pub fn new(now: SystemTime) -> Self {
        Self(Arc::new(Mutex::new(now)))
    }

    /// Records a frame received at `now`. Frames arriving out of order never move it back.
    pub fn on_frame(&self, now: SystemTime) {
        let mut last = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if now > *last {
            *last = now;
        }
    }

    /// When the newest frame arrived.
    pub fn last_rx(&self) -> SystemTime {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Returns once no frame has arrived for [`SILENCE`]: at the earliest instant the rule of 07 §9.1
/// holds, so detection takes exactly `FAILOVER_SILENCE_MS` after the last frame.
pub async fn watch<E: Clock>(clock: &E, frames: &Frames) -> Suspicion {
    loop {
        let last_rx = frames.last_rx();
        let deadline = last_rx + SILENCE;
        if clock.current() < deadline {
            clock.sleep_until(deadline).await;
        }
        // A frame that arrived while we slept moves the deadline; sleep again.
        if frames.last_rx() == last_rx {
            return Suspicion {
                reason: Reason::Silence,
                last_rx,
                at: clock.current(),
            };
        }
    }
}

/// The count of 07 §9.2: the tenure is deposed at this voter once `Silence` from `quorum`
/// distinct voters is held. Only voter indices below `n` count; the standby's `Silence` never
/// counts toward Q (07 §9.1).
#[derive(Clone, Debug)]
pub struct Deposition {
    n: usize,
    quorum: usize,
    seen: Vec<bool>,
}

impl Deposition {
    pub fn new(committee: &crate::Committee) -> Self {
        Self {
            n: committee.n(),
            quorum: committee.quorum(),
            seen: vec![false; committee.n()],
        }
    }

    /// Counts a verified `Silence` from `voter`; true once the tenure is deposed.
    pub fn add(&mut self, voter: u8) -> bool {
        if let Some(slot) = self
            .seen
            .get_mut(usize::from(voter))
            .filter(|_| usize::from(voter) < self.n)
        {
            *slot = true;
        }
        self.deposed()
    }

    pub fn deposed(&self) -> bool {
        self.seen.iter().filter(|s| **s).count() >= self.quorum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Committee;
    use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
    use vyrn_types::Mode;

    #[test]
    fn a_silent_sequencer_is_suspected_exactly_at_the_limit() {
        deterministic::Runner::new(
            deterministic::Config::new()
                .with_cycle(Duration::from_micros(1))
                .with_timeout(Some(Duration::from_secs(5))),
        )
        .start(|ctx| async move {
            let frames = Frames::new(ctx.current());
            // Heartbeats every 50 µs for 1 ms, then silence (07 §9.1: 40 missed beats).
            let beats = frames.clone();
            ctx.child("beats").spawn(move |ctx| async move {
                for _ in 0..20 {
                    ctx.sleep(Duration::from_micros(50)).await;
                    beats.on_frame(ctx.current());
                }
            });
            let s = watch(&ctx, &frames).await;
            assert_eq!(s.reason, Reason::Silence);
            assert_eq!(s.at.duration_since(s.last_rx).ok(), Some(SILENCE));
            // The sequencer spoke for 1 ms, so silence is not suspected before it stopped.
            let start = s.at - SILENCE - Duration::from_millis(1);
            assert!(s.last_rx >= start);
        });
    }

    #[test]
    fn a_live_sequencer_is_never_suspected() {
        deterministic::Runner::new(
            deterministic::Config::new()
                .with_cycle(Duration::from_micros(1))
                .with_timeout(Some(Duration::from_secs(5))),
        )
        .start(|ctx| async move {
            let frames = Frames::new(ctx.current());
            let beats = frames.clone();
            ctx.child("beats").spawn(move |ctx| async move {
                loop {
                    // 1.9 ms gaps: just under the limit.
                    ctx.sleep(Duration::from_micros(1_900)).await;
                    beats.on_frame(ctx.current());
                }
            });
            let watcher = ctx
                .child("watch")
                .spawn(move |ctx| async move { watch(&ctx, &frames).await });
            ctx.sleep(Duration::from_millis(100)).await;
            watcher.abort();
            assert!(watcher.await.is_err(), "suspected a live sequencer");
        });
    }

    #[test]
    fn deposition_needs_quorum_distinct_voters() {
        let voters = (1..=4u8)
            .map(|s| vyrn_crypto::ed25519::public_key(&[s; 32]))
            .collect();
        let c = Committee::new(Mode::Base, voters, &[]).unwrap_or_else(|e| panic!("{e}"));
        let mut d = Deposition::new(&c);
        assert!(!d.add(0));
        assert!(!d.add(0));
        assert!(!d.add(4)); // not a voter (the standby)
        assert!(!d.add(2));
        assert!(d.add(3));
    }
}
