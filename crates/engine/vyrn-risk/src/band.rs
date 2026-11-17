//! The price band (collar) of 10 §3.5 and the tick range of 10 §3.1 check 7.

use vyrn_types::{RejectReason, Tick};

use crate::account::BookSpec;
use crate::consts::RSK_BAND_MIN_TICKS;
use crate::order::{Side, Snapshot};
use crate::reject::{Reject, rej};

/// `w(ref) = max(RSK_BAND_MIN_TICKS, (ref × band_mul) >> 32)`: rounded down, so the band never
/// widens by rounding (10 §3.3).
#[inline]
pub fn band_width(reference: Tick, band_mul: u64) -> u32 {
    let w = u128::from(reference.0)
        .checked_mul(u128::from(band_mul))
        .and_then(|x| x.checked_shr(32))
        .and_then(|x| u32::try_from(x).ok())
        .unwrap_or(u32::MAX);
    w.max(RSK_BAND_MIN_TICKS)
}

impl BookSpec {
    /// The aggressive edge of the band for `side` (10 §3.5), clamped to `[min_tick, max_tick]`.
    ///
    /// - Buy: `ref_ask + w(ref_ask)`, where `ref_ask` is the snapshot ask, or `ref_tick` when the
    ///   ask side is empty.
    /// - Sell: `ref_bid − w(ref_bid)`, saturating at `min_tick`, likewise.
    ///
    /// `None` when the side is empty and there is no `ref_tick` either: then no band applies and
    /// only the tick range does (a spec gap: 10 §3.5 does not say what an empty book's band is).
    pub fn band_edge(&self, snap: &Snapshot, side: Side) -> Option<Tick> {
        let pick = |t: Tick| if t.0 != 0 { t } else { snap.ref_tick };
        match side {
            Side::Buy => {
                let r = pick(snap.ask);
                if r.0 == 0 {
                    return None;
                }
                let e = r.0.saturating_add(band_width(r, self.band_mul));
                Some(Tick(e.min(self.max_tick.0)))
            }
            Side::Sell => {
                let r = pick(snap.bid);
                if r.0 == 0 {
                    return None;
                }
                let e = r.0.saturating_sub(band_width(r, self.band_mul));
                Some(Tick(e.max(self.min_tick.0)))
            }
        }
    }

    /// Check 7 (10 §3.1, 04 M6). In this order, the first failure is the reject:
    ///
    /// 1. `tick < min_tick` (tick 0 included): `BAD_TICK`, detail `min_tick`.
    /// 2. `tick > max_tick`: `BAD_TICK`, detail `max_tick`.
    /// 3. Buy above its band edge, or sell below it: `BAD_TICK`, detail the edge.
    ///
    /// A buy below the bid or a sell above the ask is never out of band.
    pub fn check_tick(&self, snap: &Snapshot, side: Side, tick: Tick) -> Result<(), Reject> {
        if tick < self.min_tick {
            return Err(rej(RejectReason::BadTick, self.min_tick.0));
        }
        if tick > self.max_tick {
            return Err(rej(RejectReason::BadTick, self.max_tick.0));
        }
        let Some(edge) = self.band_edge(snap, side) else {
            return Ok(());
        };
        let outside = match side {
            Side::Buy => tick > edge,
            Side::Sell => tick < edge,
        };
        if outside {
            return Err(rej(RejectReason::BadTick, edge.0));
        }
        Ok(())
    }
}
