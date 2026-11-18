//! The bridge signer table: L1 rotation number → bridge and guardian keys (09 §6.7, 08 §9.5).
//!
//! **Owner.** This crate. The table is a key table that changes only at an epoch boundary (E9),
//! like the vote and sequencer keys, so it lives with them. `vyrn-chain` sits above this crate
//! (11 §1.4) and reads the table through its own `Epochs::bridge_signers`; this crate knows no
//! EIP-712 and no `vyrn-chain` type, only 20-byte EVM addresses.
//!
//! **Writer.** Governance approves a new set (`SetParam` on the signer table, 09 §6.7 step 1).
//! The approved set is [`BridgeSignerTable::schedule`]d for the first boundary after approval and
//! becomes active at [`BridgeSignerTable::activate`] of that epoch, which every node calls when
//! its [`crate::Timetable`] applies `Activated`. From that epoch on, the validators sign
//! `rotateSigners` with the previous set (step 2), and L1 enforces its own 72 h queue (step 3).
//!
//! **Readers.** Guardians and relayers look up any set by rotation number with
//! [`BridgeSignerTable::get`]: posts accepted under an earlier set stay claimable (step 4), so
//! every activated set stays readable.
//!
//! **Rejects** ([`BridgeErr`]): a rotation number that is not the next one, an activation epoch
//! that is not after the active epoch, and a zero or repeated key within either list (the
//! contract's `_writeSet` check).

use std::collections::BTreeMap;
use thiserror::Error;
use vyrn_types::Epoch;

/// An EVM address.
pub type EvmAddress = [u8; 20];
/// Bridge keys and guardian keys per set (09 §2.2).
pub const BRIDGE_SIGNERS: usize = 5;

/// One signer set, keys in `OpIdx` order (09 §6.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeSigners {
    /// L1 rotation number; genesis is 0.
    pub rotation_no: u64,
    /// Bridge keys BK_0..BK_4.
    pub bridge_keys: [EvmAddress; BRIDGE_SIGNERS],
    /// Guardian keys GK_0..GK_4.
    pub guardian_keys: [EvmAddress; BRIDGE_SIGNERS],
}

impl BridgeSigners {
    pub(crate) fn well_formed(&self) -> bool {
        let ok = |keys: &[EvmAddress; BRIDGE_SIGNERS]| {
            keys.iter()
                .enumerate()
                .all(|(i, k)| *k != [0u8; 20] && !keys[..i].contains(k))
        };
        ok(&self.bridge_keys) && ok(&self.guardian_keys)
    }
}

/// Why a set is not scheduled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BridgeErr {
    #[error("rotation {got} is not the next rotation {want}")]
    Rotation { got: u64, want: u64 },
    #[error("epoch {from:?} is before the active epoch or a pending rotation's ({active:?})")]
    Epoch { from: Epoch, active: Epoch },
    #[error("a key is zero or repeated within its list")]
    Malformed,
}

/// The table every node holds, identical on every node that applied the same records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeSignerTable {
    active: Epoch,
    sets: BTreeMap<u64, BridgeSigners>,
    /// Approved sets by the epoch they activate at, at most one per rotation number.
    pending: BTreeMap<u64, (Epoch, BridgeSigners)>,
}

impl BridgeSignerTable {
    /// The table at genesis: `set` is rotation 0, active from epoch 0.
    pub fn genesis(set: BridgeSigners) -> Result<Self, BridgeErr> {
        if set.rotation_no != 0 {
            return Err(BridgeErr::Rotation {
                got: set.rotation_no,
                want: 0,
            });
        }
        if !set.well_formed() {
            return Err(BridgeErr::Malformed);
        }
        Ok(Self {
            active: Epoch(0),
            sets: BTreeMap::from([(0, set)]),
            pending: BTreeMap::new(),
        })
    }

    /// The set with rotation number `rotation_no`, once its epoch has activated.
    pub fn get(&self, rotation_no: u64) -> Option<&BridgeSigners> {
        self.sets.get(&rotation_no)
    }

    /// The newest active set.
    pub fn current(&self) -> &BridgeSigners {
        // `genesis` inserts rotation 0 and nothing removes a set.
        self.sets
            .last_key_value()
            .map(|(_, s)| s)
            .unwrap_or_else(|| unreachable!("the genesis set is never removed"))
    }

    /// A governance-approved `set` that activates at the boundary into `from`.
    pub fn schedule(&mut self, set: BridgeSigners, from: Epoch) -> Result<(), BridgeErr> {
        let newest = self
            .pending
            .last_key_value()
            .map_or(self.current().rotation_no, |(r, _)| *r);
        let want = newest.saturating_add(1);
        if set.rotation_no != want {
            return Err(BridgeErr::Rotation {
                got: set.rotation_no,
                want,
            });
        }
        // Not before the active epoch, nor before a rotation still pending: sets activate in
        // rotation order, so each accepted schedule activates at its own boundary.
        let floor = self
            .pending
            .last_key_value()
            .map_or(self.active, |(_, (e, _))| {
                Epoch(e.0.saturating_sub(1)).max(self.active)
            });
        if from <= floor {
            return Err(BridgeErr::Epoch {
                from,
                active: floor,
            });
        }
        if !set.well_formed() {
            return Err(BridgeErr::Malformed);
        }
        self.pending.insert(set.rotation_no, (from, set));
        Ok(())
    }

    /// Epoch `epoch` activated: every set scheduled for it or earlier becomes active, in
    /// rotation order. A skipped epoch activates its sets at the next activation.
    pub fn activate(&mut self, epoch: Epoch) {
        self.active = self.active.max(epoch);
        while let Some(entry) = self.pending.first_entry() {
            if entry.get().0 > self.active {
                break;
            }
            let (_, set) = entry.remove();
            self.sets.insert(set.rotation_no, set);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(rotation_no: u64, seed: u8) -> BridgeSigners {
        BridgeSigners {
            rotation_no,
            bridge_keys: [0u8, 1, 2, 3, 4].map(|i| [seed + i; 20]),
            guardian_keys: [0u8, 1, 2, 3, 4].map(|i| [seed + 0x10 + i; 20]),
        }
    }

    #[test]
    fn a_set_becomes_readable_only_when_its_epoch_activates() {
        let mut t = BridgeSignerTable::genesis(set(0, 1)).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(t.schedule(set(1, 0x40), Epoch(3)), Ok(()));
        t.activate(Epoch(2));
        assert_eq!(t.get(1), None);
        assert_eq!(t.current().rotation_no, 0);
        t.activate(Epoch(3));
        assert_eq!(t.get(1), Some(&set(1, 0x40)));
        // Posts under rotation 0 stay checkable.
        assert_eq!(t.get(0), Some(&set(0, 1)));
        assert_eq!(t.current().rotation_no, 1);
    }

    #[test]
    fn a_skipped_epoch_activates_its_set_at_the_next_activation() {
        let mut t = BridgeSignerTable::genesis(set(0, 1)).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(t.schedule(set(1, 0x40), Epoch(2)), Ok(()));
        assert_eq!(t.schedule(set(2, 0x80), Epoch(4)), Ok(()));
        t.activate(Epoch(3));
        assert_eq!((t.get(1).is_some(), t.get(2).is_some()), (true, false));
        t.activate(Epoch(5));
        assert_eq!(t.current().rotation_no, 2);
    }

    #[test]
    fn schedule_rejects_gaps_the_past_and_malformed_sets() {
        let mut t = BridgeSignerTable::genesis(set(0, 1)).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            t.schedule(set(2, 0x40), Epoch(3)),
            Err(BridgeErr::Rotation { got: 2, want: 1 })
        );
        t.activate(Epoch(4));
        assert_eq!(
            t.schedule(set(1, 0x40), Epoch(4)),
            Err(BridgeErr::Epoch {
                from: Epoch(4),
                active: Epoch(4)
            })
        );
        let mut dup = set(1, 0x40);
        dup.guardian_keys[4] = dup.guardian_keys[0];
        assert_eq!(t.schedule(dup, Epoch(5)), Err(BridgeErr::Malformed));
        let mut zero = set(1, 0x40);
        zero.bridge_keys[2] = [0; 20];
        assert_eq!(t.schedule(zero, Epoch(5)), Err(BridgeErr::Malformed));
        // A later rotation may not activate before an earlier pending one; the same epoch is fine.
        assert_eq!(t.schedule(set(1, 0x40), Epoch(7)), Ok(()));
        assert!(matches!(
            t.schedule(set(2, 0x80), Epoch(6)),
            Err(BridgeErr::Epoch { .. })
        ));
        assert_eq!(t.schedule(set(2, 0x80), Epoch(7)), Ok(()));
        t.activate(Epoch(7));
        assert_eq!(t.current().rotation_no, 2);
        assert!(matches!(
            BridgeSignerTable::genesis(set(1, 1)),
            Err(BridgeErr::Rotation { .. })
        ));
    }
}
