//! `L1Attest` (09 §6.3): operators attest the `Deposited` events of finalized L1 blocks, and the
//! state machine credits deposit nonce n once `CHN_ATTEST_QUORUM` (3) distinct operators have
//! attested an identical event for n, in nonce order only.
//!
//! **Spec gaps (readings chosen).**
//! - *`L1Event`:* only `Deposited` is modelled; its fields are those of `IVyrnBridge.Deposited`
//!   (`nonce, token, amount, ownerKind, owner, sender`). Other contract events are a follow-up.
//! - *Conflicting attestations:* an operator's first attestation for a nonce counts; a later,
//!   different one from the same operator is refused (`Conflict`) and does not replace it.
//! - *Encoding:* not fixed here; the tally works on decoded events (follow-up).

use std::collections::BTreeMap;

use crate::eip712::{Address, U256};
use crate::tesla::OpIdx;

/// `CHN_ATTEST_QUORUM` (09 §17.1).
pub const ATTEST_QUORUM: usize = 3;

/// `Deposited` as the bridge emits it (contracts/src/IVyrnBridge.sol).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deposited {
    /// The contract's deposit nonce.
    pub nonce: u64,
    /// The ERC-20 token.
    pub token: Address,
    /// Amount, uint256 big-endian.
    pub amount: U256,
    /// 0 Ed25519 key, 1 EVM address.
    pub owner_kind: u8,
    /// The owner key or address.
    pub owner: [u8; 32],
    /// The depositor; the default `exit_address`.
    pub sender: Address,
}

/// `L1Attest` (09 §6.3), item 0x20.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L1Attest {
    /// A finalized L1 block number.
    pub l1_block: u64,
    /// Its hash.
    pub l1_block_hash: [u8; 32],
    /// Its events, in log order.
    pub events: Vec<Deposited>,
}

/// Why an attested event is not counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AttestError {
    /// The nonce is already credited.
    #[error("nonce {0} already credited")]
    Credited(u64),
    /// The operator already attested a different event for this nonce.
    #[error("operator {0} attested a different event for this nonce")]
    Conflict(OpIdx),
}

/// The deposit tally: attestations per nonce, and the next nonce to credit.
#[derive(Clone, Debug, Default)]
pub struct DepositTally {
    next: u64,
    pending: BTreeMap<u64, BTreeMap<OpIdx, Deposited>>,
}

impl DepositTally {
    /// A tally whose next creditable nonce is `next` (the bridge's first nonce, or the last
    /// credited + 1 on resume).
    pub fn new(next: u64) -> Self {
        Self {
            next,
            pending: BTreeMap::new(),
        }
    }

    /// The next nonce to credit.
    pub fn next_nonce(&self) -> u64 {
        self.next
    }

    /// Records `op`'s attestation of every event in `a`. Returns one result per event.
    pub fn attest(&mut self, op: OpIdx, a: &L1Attest) -> Vec<Result<(), AttestError>> {
        a.events.iter().map(|e| self.attest_event(op, e)).collect()
    }

    fn attest_event(&mut self, op: OpIdx, e: &Deposited) -> Result<(), AttestError> {
        if e.nonce < self.next {
            return Err(AttestError::Credited(e.nonce));
        }
        let by_op = self.pending.entry(e.nonce).or_default();
        match by_op.get(&op) {
            Some(prev) if prev != e => Err(AttestError::Conflict(op)),
            Some(_) => Ok(()),
            None => {
                by_op.insert(op, *e);
                Ok(())
            }
        }
    }

    /// Credits, in nonce order, every deposit from the next nonce on that ≥ 3 operators attested
    /// identically, stopping at the first nonce without a quorum.
    pub fn credit(&mut self) -> Vec<Deposited> {
        let mut out = Vec::new();
        while let Some(by_op) = self.pending.get(&self.next) {
            let mut counts: BTreeMap<&Deposited, usize> = BTreeMap::new();
            for e in by_op.values() {
                *counts.entry(e).or_default() += 1;
            }
            let Some(e) = counts
                .into_iter()
                .find(|(_, n)| *n >= ATTEST_QUORUM)
                .map(|(e, _)| *e)
            else {
                break;
            };
            self.pending.remove(&self.next);
            out.push(e);
            self.next = self.next.saturating_add(1);
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn dep(nonce: u64, amount: u8) -> Deposited {
        let mut a = [0u8; 32];
        a[31] = amount;
        Deposited {
            nonce,
            token: [1; 20],
            amount: a,
            owner_kind: 1,
            owner: [2; 32],
            sender: [3; 20],
        }
    }

    fn att(events: Vec<Deposited>) -> L1Attest {
        L1Attest {
            l1_block: 100,
            l1_block_hash: [9; 32],
            events,
        }
    }

    #[test]
    fn credits_at_three_identical_in_nonce_order() {
        let mut t = DepositTally::new(1);
        // Nonce 2 reaches quorum first but waits for nonce 1.
        for op in 0..3 {
            t.attest(op, &att(vec![dep(2, 5)]));
        }
        t.attest(0, &att(vec![dep(1, 7)]));
        t.attest(1, &att(vec![dep(1, 7)]));
        assert!(t.credit().is_empty());
        // A third operator with a different amount does not make a quorum.
        t.attest(2, &att(vec![dep(1, 8)]));
        assert!(t.credit().is_empty());
        // An operator cannot change its attestation; repeating it is a no-op.
        assert_eq!(
            t.attest(2, &att(vec![dep(1, 7)])),
            vec![Err(AttestError::Conflict(2))]
        );
        assert_eq!(t.attest(1, &att(vec![dep(1, 7)])), vec![Ok(())]);
        assert!(t.credit().is_empty(), "the same operator twice is one vote");
        t.attest(3, &att(vec![dep(1, 7)]));
        assert_eq!(t.credit(), vec![dep(1, 7), dep(2, 5)]);
        assert_eq!(t.next_nonce(), 3);
        assert_eq!(
            t.attest(4, &att(vec![dep(2, 5)])),
            vec![Err(AttestError::Credited(2))]
        );
    }
}
