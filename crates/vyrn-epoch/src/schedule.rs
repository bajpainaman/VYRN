//! The schedule (08 §2): slots, `home(e)`, the boundary T, and the three ways the log revises it.
//!
//! **Slots.** Epoch e is nominally `[G + 8h·e, G + 8h·(e+1))` in TAI nanoseconds (E1). A client
//! needs only `G` to compute the default schedule; [`Timetable`] adds the logged revisions.
//!
//! **Revisions** ([`ScheduleRecord`]), applied in log order with the `rx_ts` of the record:
//!
//! | Record | Valid when | Effect |
//! |---|---|---|
//! | `Skip{epoch}` | `epoch` ≥ the target, logged ≥ `EPO_CONFIG_LEAD_S` before the boundary into it | the epoch is never used; the target moves past it |
//! | `HomeOverride{epoch, home}` | same lead rule | `home(epoch)` changes |
//! | `Hold{epoch, t_new}` | `epoch` is active, `t_new = T + EPO_HOLD_S`, logged before T | T moves; past the target's slot the target moves on |
//! | `Activated{epoch}` | `epoch` is the target | the target becomes active; T becomes its nominal end |
//!
//! A hold never shortens anything, and nothing bounds T (08 §2.5).
//!
//! Spec gap: leap seconds (`EpoConfig.flags` bit2) shift the TAI value of later boundaries by an
//! announced amount that 08 §2.1 does not encode. This crate assumes none [Guessing]; a leap
//! record is a follow-up.

use crate::{EPO_CONFIG_LEAD_S, EPO_HOLD_S, EPOCH_NS, NS_PER_S};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use vyrn_types::{Epoch, Hash, HomeCode, Nanos};

/// `home(e)` with no override: `[TYO, LDN, NYC][e mod 3]` (08 E1, 09 §2).
pub const fn default_home(e: Epoch) -> HomeCode {
    match e.0 % 3 {
        0 => HomeCode::Tyo,
        1 => HomeCode::Ldn,
        _ => HomeCode::Nyc,
    }
}

/// The nominal start of slot e, `G + 8h·e`; `None` past `u64` nanoseconds.
pub fn slot_start(genesis: Nanos, e: Epoch) -> Option<Nanos> {
    EPOCH_NS
        .checked_mul(u64::from(e.0))
        .and_then(|d| genesis.0.checked_add(d))
        .map(Nanos)
}

/// A change to the schedule, as logged (08 §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleRecord {
    /// `EpoConfig{epoch, flags.skip}`.
    Skip { epoch: Epoch },
    /// `HomeOverride{epoch, home}` (09 §2.10; BASE: admin).
    HomeOverride { epoch: Epoch, home: HomeCode },
    /// `EpoHold{epoch, t_new}` from the go/no-go.
    Hold { epoch: Epoch, t_new: Nanos },
    /// cert(e, S) verified and the opening block of `epoch` final (`EpoActivated`).
    Activated { epoch: Epoch },
}

/// Why a [`ScheduleRecord`] does not apply. A rejected record changes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ScheduleErr {
    #[error("epoch {got:?} is not open for this change (target {target:?})")]
    Epoch { got: Epoch, target: Epoch },
    #[error("logged at {at:?}, later than {deadline:?} (EPO_CONFIG_LEAD_S or T)")]
    Late { at: Nanos, deadline: Nanos },
    #[error("t_new {got:?} is not T + EPO_HOLD_S = {want:?}")]
    HoldTime { got: Nanos, want: Nanos },
    #[error("the schedule passes u64 nanoseconds")]
    Overflow,
}

/// The next boundary, as the schedule stands now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Boundary {
    /// The active epoch e.
    pub from: Epoch,
    /// The target: e+1, or later after a skip or a long hold.
    pub to: Epoch,
    /// T in TAI nanoseconds.
    pub t: Nanos,
    pub from_home: HomeCode,
    pub to_home: HomeCode,
}

impl Boundary {
    /// The handoff stays in one metro (08 §2.5, §6.2 last row).
    pub fn in_metro(&self) -> bool {
        self.from_home == self.to_home
    }
}

/// The schedule as revised by the log. Every node that applies the same records holds the same
/// timetable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timetable {
    genesis: Nanos,
    active: Epoch,
    t: Nanos,
    target: Epoch,
    overrides: BTreeMap<Epoch, HomeCode>,
    skips: BTreeSet<Epoch>,
}

impl Timetable {
    /// Epoch 0 is active from `genesis`; the first boundary is to epoch 1 at `G + 8h`.
    pub fn new(genesis: Nanos) -> Result<Self, ScheduleErr> {
        let t = slot_start(genesis, Epoch(1)).ok_or(ScheduleErr::Overflow)?;
        Ok(Self {
            genesis,
            active: Epoch(0),
            t,
            target: Epoch(1),
            overrides: BTreeMap::new(),
            skips: BTreeSet::new(),
        })
    }

    pub fn genesis(&self) -> Nanos {
        self.genesis
    }

    pub fn active(&self) -> Epoch {
        self.active
    }

    /// `home(e)` after any override.
    pub fn home(&self, e: Epoch) -> HomeCode {
        self.overrides
            .get(&e)
            .copied()
            .unwrap_or_else(|| default_home(e))
    }

    pub fn boundary(&self) -> Boundary {
        Boundary {
            from: self.active,
            to: self.target,
            t: self.t,
            from_home: self.home(self.active),
            to_home: self.home(self.target),
        }
    }

    /// Applies one logged record at its `rx_ts` `at`.
    pub fn apply(&mut self, record: ScheduleRecord, at: Nanos) -> Result<(), ScheduleErr> {
        match record {
            ScheduleRecord::Skip { epoch } => {
                self.check_lead(epoch, at)?;
                self.skips.insert(epoch);
                if epoch == self.target {
                    self.target = self.next_unskipped(epoch)?;
                    self.t = self.slot(self.target)?;
                }
            }
            ScheduleRecord::HomeOverride { epoch, home } => {
                self.check_lead(epoch, at)?;
                self.overrides.insert(epoch, home);
            }
            ScheduleRecord::Hold { epoch, t_new } => {
                if epoch != self.active {
                    return Err(ScheduleErr::Epoch {
                        got: epoch,
                        target: self.target,
                    });
                }
                // The go/no-go is before T; a hold logged at or after T is too late (§2.6).
                if at >= self.t {
                    return Err(ScheduleErr::Late {
                        at,
                        deadline: self.t,
                    });
                }
                let want = add_s(self.t, EPO_HOLD_S)?;
                if t_new != want {
                    return Err(ScheduleErr::HoldTime { got: t_new, want });
                }
                self.t = t_new;
                // Past the nominal end of the target's slot, its keys and sequencer have expired
                // (§2.5): retarget. A T exactly at the slot end would leave a zero-length epoch,
                // so it retargets too [Guessing].
                while self.t >= self.slot(Epoch(self.target.0.saturating_add(1)))? {
                    self.target = self.next_unskipped(self.target)?;
                }
                // A retarget across a skipped slot waits for the new target's slot, as a planned
                // skip does: the old home keeps the book through the skipped slot.
                self.t = self.t.max(self.slot(self.target)?);
            }
            ScheduleRecord::Activated { epoch } => {
                if epoch != self.target {
                    return Err(ScheduleErr::Epoch {
                        got: epoch,
                        target: self.target,
                    });
                }
                self.active = epoch;
                self.target = self.next_unskipped(epoch)?;
                self.t = self.slot(self.target)?;
                // Revisions of epochs that can no longer be targeted are dead state.
                self.overrides.retain(|e, _| *e >= epoch);
                self.skips.retain(|e| *e > epoch);
            }
        }
        Ok(())
    }

    /// Skips and overrides: the epoch is the target or later, and the record is logged at least
    /// `EPO_CONFIG_LEAD_S` before the boundary into it.
    fn check_lead(&self, epoch: Epoch, at: Nanos) -> Result<(), ScheduleErr> {
        if epoch < self.target {
            return Err(ScheduleErr::Epoch {
                got: epoch,
                target: self.target,
            });
        }
        let into = if epoch == self.target {
            self.t
        } else {
            self.slot(epoch)?
        };
        let deadline = Nanos(into.0.saturating_sub(EPO_CONFIG_LEAD_S * NS_PER_S));
        if at > deadline {
            return Err(ScheduleErr::Late { at, deadline });
        }
        Ok(())
    }

    fn next_unskipped(&self, after: Epoch) -> Result<Epoch, ScheduleErr> {
        let mut e = after;
        loop {
            e = Epoch(e.0.checked_add(1).ok_or(ScheduleErr::Overflow)?);
            if !self.skips.contains(&e) {
                return Ok(e);
            }
        }
    }

    fn slot(&self, e: Epoch) -> Result<Nanos, ScheduleErr> {
        slot_start(self.genesis, e).ok_or(ScheduleErr::Overflow)
    }
}

fn add_s(t: Nanos, s: u64) -> Result<Nanos, ScheduleErr> {
    t.0.checked_add(s * NS_PER_S)
        .map(Nanos)
        .ok_or(ScheduleErr::Overflow)
}

/// The configuration of one epoch, fixed in the log of the epoch before (08 §2.3).
///
/// Spec gap: 08 gives no byte encoding of `EpoConfig` (Requests to 01, item 7), so this crate
/// carries the fields only; the log's encoding is `vyrn-log`'s once 01 fixes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpoConfig {
    /// The epoch it configures.
    pub epoch: Epoch,
    /// `home(epoch)` after any override.
    pub home: HomeCode,
    /// Nominal start (TAI): T of the epoch before it.
    pub t_start: Nanos,
    /// The roster of all three homes (08 §9.6); [`crate::Membership::from_roster`] checks it.
    pub roster_hash: Hash,
    /// Roster indices of the home's `vyrn-seq` boxes: `[primary F1, warm standby F2]` (01 §14.4).
    pub seq_order: [u8; 2],
    pub lane_map_hash: Hash,
    /// Lane count of each home's boxes, in [`crate::HOMES`] order (REF 49). All three homes, so a
    /// carried-forward configuration stays right when `home` changes (08 §2.3).
    pub n_lanes: [u8; 3],
    /// Engine semantics version in force for the epoch (§9.4).
    pub version: u32,
    /// The endpoint table of all three homes (08 §11.1).
    pub endpoint_hash: Hash,
    pub flags: u16,
    /// Scheme of every live key and signature of `epoch` (01 §3, §14.20); the roster's keys are
    /// of this scheme.
    pub sig_scheme: u8,
}

impl EpoConfig {
    pub const FLAG_SKIP: u16 = 1 << 0;
    pub const FLAG_DATE_ROLL: u16 = 1 << 1;
    pub const FLAG_LEAP: u16 = 1 << 2;

    /// Lane count of `home(epoch)`'s boxes.
    pub fn lanes(&self) -> u8 {
        let i = crate::HOMES
            .iter()
            .position(|h| *h == self.home)
            .unwrap_or(0);
        self.n_lanes[i]
    }

    /// The configuration in force for `boundary.to` (08 §2.3): `published` if it names that
    /// epoch and was final at least `EPO_CONFIG_LEAD_S` before T, else `prev` carried forward
    /// with `home`, `t_start` and `seq_order` recomputed from the schedule. A missing record
    /// never blocks a handoff.
    ///
    /// `seq_order` from the schedule is 09's `seq_op(e)` in CHAIN and fixed in BASE; this crate
    /// has no roster, so the carried value keeps `prev.seq_order` [Guessing; spec gap].
    pub fn in_force(prev: &Self, published: Option<(&Self, Nanos)>, boundary: &Boundary) -> Self {
        let deadline = boundary.t.0.saturating_sub(EPO_CONFIG_LEAD_S * NS_PER_S);
        match published {
            Some((cfg, final_at)) if cfg.epoch == boundary.to && final_at.0 <= deadline => *cfg,
            _ => Self {
                epoch: boundary.to,
                home: boundary.to_home,
                t_start: boundary.t,
                flags: prev.flags & !Self::FLAG_SKIP,
                ..*prev
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: Nanos = Nanos(1_000 * NS_PER_S);

    fn at_before(t: Nanos, s: u64) -> Nanos {
        Nanos(t.0 - s * NS_PER_S)
    }

    #[test]
    fn default_schedule_follows_the_sun() {
        let tt = Timetable::new(G).unwrap_or_else(|e| panic!("{e}"));
        let b = tt.boundary();
        assert_eq!((b.from, b.to), (Epoch(0), Epoch(1)));
        assert_eq!(b.t, Nanos(G.0 + 28_800 * NS_PER_S));
        assert_eq!((b.from_home, b.to_home), (HomeCode::Tyo, HomeCode::Ldn));
        assert_eq!(default_home(Epoch(5)), HomeCode::Nyc);
        assert_eq!(default_home(Epoch(6)), HomeCode::Tyo);
    }

    #[test]
    fn a_hold_moves_t_and_a_long_hold_retargets() {
        let mut tt = Timetable::new(G).unwrap_or_else(|e| panic!("{e}"));
        let t0 = tt.boundary().t;
        let hold = |t: Nanos| ScheduleRecord::Hold {
            epoch: Epoch(0),
            t_new: Nanos(t.0 + EPO_HOLD_S * NS_PER_S),
        };
        // A hold must name exactly T + 900 s.
        assert!(matches!(
            tt.apply(
                ScheduleRecord::Hold {
                    epoch: Epoch(0),
                    t_new: Nanos(t0.0 + 1)
                },
                at_before(t0, 10)
            ),
            Err(ScheduleErr::HoldTime { .. })
        ));
        // A hold at T is too late.
        assert!(matches!(
            tt.apply(hold(t0), t0),
            Err(ScheduleErr::Late { .. })
        ));
        assert_eq!(tt.apply(hold(t0), at_before(t0, 10)), Ok(()));
        assert_eq!(tt.boundary().t, Nanos(t0.0 + 900 * NS_PER_S));
        assert_eq!(tt.boundary().to, Epoch(1));
        // 32 holds of 900 s = 8 h: T reaches the end of slot 1, so the target moves to 2.
        for _ in 1..32 {
            let t = tt.boundary().t;
            assert_eq!(tt.apply(hold(t), at_before(t, 10)), Ok(()));
        }
        let b = tt.boundary();
        assert_eq!(b.t, Nanos(t0.0 + EPOCH_NS));
        assert_eq!((b.to, b.to_home), (Epoch(2), HomeCode::Nyc));
    }

    #[test]
    fn a_long_hold_across_a_skip_waits_for_the_next_slot() {
        let mut tt = Timetable::new(G).unwrap_or_else(|e| panic!("{e}"));
        let t0 = tt.boundary().t;
        let skip = ScheduleRecord::Skip { epoch: Epoch(2) };
        assert_eq!(tt.apply(skip, G), Ok(()));
        for _ in 0..32 {
            let t = tt.boundary().t;
            let hold = ScheduleRecord::Hold {
                epoch: Epoch(0),
                t_new: Nanos(t.0 + EPO_HOLD_S * NS_PER_S),
            };
            assert_eq!(tt.apply(hold, at_before(t, 10)), Ok(()));
        }
        // T reached the end of slot 1; slot 2 is skipped, so the handoff is to 3 at its start.
        let b = tt.boundary();
        assert_eq!((b.to, b.t), (Epoch(3), Nanos(t0.0 + 2 * EPOCH_NS)));
    }

    #[test]
    fn skips_and_overrides_need_the_config_lead() {
        let mut tt = Timetable::new(G).unwrap_or_else(|e| panic!("{e}"));
        let t = tt.boundary().t;
        let skip = ScheduleRecord::Skip { epoch: Epoch(1) };
        assert!(matches!(
            tt.apply(skip, at_before(t, EPO_CONFIG_LEAD_S - 1)),
            Err(ScheduleErr::Late { .. })
        ));
        assert_eq!(tt.apply(skip, at_before(t, EPO_CONFIG_LEAD_S)), Ok(()));
        let b = tt.boundary();
        assert_eq!(
            (b.from, b.to, b.t),
            (Epoch(0), Epoch(2), Nanos(t.0 + EPOCH_NS))
        );
        // An override of epoch 2 to the active home makes the handoff in-metro.
        let ov = ScheduleRecord::HomeOverride {
            epoch: Epoch(2),
            home: HomeCode::Tyo,
        };
        assert_eq!(tt.apply(ov, t), Ok(()));
        assert!(tt.boundary().in_metro());
        // Skipped epoch 1 can no longer be revised.
        assert!(matches!(
            tt.apply(
                ScheduleRecord::HomeOverride {
                    epoch: Epoch(1),
                    home: HomeCode::Nyc
                },
                G
            ),
            Err(ScheduleErr::Epoch { .. })
        ));
    }

    #[test]
    fn activation_after_a_hold_shortens_the_next_epoch() {
        let mut tt = Timetable::new(G).unwrap_or_else(|e| panic!("{e}"));
        let t0 = tt.boundary().t;
        let held = Nanos(t0.0 + EPO_HOLD_S * NS_PER_S);
        let hold = ScheduleRecord::Hold {
            epoch: Epoch(0),
            t_new: held,
        };
        assert_eq!(tt.apply(hold, at_before(t0, 10)), Ok(()));
        assert!(matches!(
            tt.apply(ScheduleRecord::Activated { epoch: Epoch(2) }, held),
            Err(ScheduleErr::Epoch { .. })
        ));
        assert_eq!(
            tt.apply(ScheduleRecord::Activated { epoch: Epoch(1) }, held),
            Ok(())
        );
        let b = tt.boundary();
        assert_eq!(
            (b.from, b.to, b.t),
            (Epoch(1), Epoch(2), Nanos(t0.0 + EPOCH_NS))
        );
    }

    #[test]
    fn a_late_config_is_carried_forward() {
        let tt = Timetable::new(G).unwrap_or_else(|e| panic!("{e}"));
        let b = tt.boundary();
        let prev = EpoConfig {
            epoch: Epoch(0),
            home: HomeCode::Tyo,
            t_start: G,
            roster_hash: Hash([1; 32]),
            seq_order: [4, 5],
            lane_map_hash: Hash([2; 32]),
            n_lanes: [49, 49, 11],
            version: 3,
            endpoint_hash: Hash([3; 32]),
            flags: EpoConfig::FLAG_SKIP,
            sig_scheme: 0,
        };
        let next = EpoConfig {
            epoch: Epoch(1),
            version: 4,
            ..prev
        };
        let on_time = at_before(b.t, EPO_CONFIG_LEAD_S);
        assert_eq!(EpoConfig::in_force(&prev, Some((&next, on_time)), &b), next);
        let late = Nanos(on_time.0 + 1);
        let carried = EpoConfig::in_force(&prev, Some((&next, late)), &b);
        assert_eq!(
            (
                carried.epoch,
                carried.home,
                carried.t_start,
                carried.version
            ),
            (Epoch(1), HomeCode::Ldn, b.t, 3)
        );
        assert_eq!(carried.flags & EpoConfig::FLAG_SKIP, 0);
    }
}
