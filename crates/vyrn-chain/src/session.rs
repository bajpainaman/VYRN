//! `SessionOpen` (09 §5.2): the item (kind 0x01) a wallet signs to open a trading session, its
//! encoding and the validity checks 2–4 against the state after the parent chain block.
//!
//! Check 1 (the wallet signature against the account's `owner`) belongs to the `TxEnvelope`
//! (09 §4.4), which carries the signature; it is not part of this body.
//!
//! **Spec gap (encoding).** 09 §5.2 gives the fields, not the bytes. This crate encodes them in
//! field order, little-endian (01 §3), with `bound_addr` as `family ‖ ip ‖ le16(port)` (19 B) and
//! `n_epochs` as one byte followed by `n_epochs × 5` anchors of 32 B: 106 + 160 · n bytes.
//! `anchors[k][s]` is `A(first_epoch + k, s)`.

use vyrn_crypto::hash::hash;
use vyrn_crypto::x25519;
use vyrn_types::{AccountId, Epoch, Hash};

use crate::codec::{Reader, Writer};

/// `CHN_SESSION_MAX_EPOCHS` (09 §17.1).
pub const SESSION_MAX_EPOCHS: u8 = 3;
/// `CHN_SESSION_BOND_MIN`: 1,000 USDC in micro-units (09 §17.1).
pub const SESSION_BOND_MIN: u64 = 1_000_000_000;
/// `CHN_BOND_PER_MSGRATE`: 0.01 USDC per message per second, in micro-units (09 §17.1).
pub const BOND_PER_MSGRATE: u64 = 10_000;
/// The latest epoch a session may cover, relative to the current one (09 §5.2 check 2).
pub const SESSION_LEAD_EPOCHS: u32 = 3;
/// Operators per committee: one anchor per possible sequencer (09 §5.2).
pub const COMMITTEE: usize = 5;
/// The encoded length without anchors.
pub const FIXED_LEN: usize = 106;

/// The source address a session is bound to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BoundAddr {
    /// Address family (spec gap: 4 or 6, as 04 uses it).
    pub family: u8,
    /// IPv6, or IPv4-mapped.
    pub ip: [u8; 16],
    /// UDP port.
    pub port: u16,
}

/// `SessionOpen` (09 §5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionOpen {
    /// The account that opens the session.
    pub account: AccountId,
    /// The book group the session trades.
    pub book_group: u16,
    /// Fresh per session; never reused.
    pub x25519_pub: [u8; 32],
    /// Ed25519 session signing key (forced path, small items).
    pub sign_pub: [u8; 32],
    /// The bound source address.
    pub bound_addr: BoundAddr,
    /// USDC micro-units.
    pub bond: u64,
    /// The session's rate limit.
    pub max_msgs_per_s: u32,
    /// The first epoch the session covers.
    pub first_epoch: Epoch,
    /// `A(e, s)` per covered epoch and per possible sequencer; `len()` is `n_epochs`.
    pub anchors: Vec<[Hash; COMMITTEE]>,
}

/// Why a `SessionOpen` is invalid (09 §5.2 checks 2–4), and why it does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpenReject {
    /// Not the encoding above.
    #[error("malformed SessionOpen")]
    Malformed,
    /// `n_epochs` ∉ 1 ..= 3.
    #[error("n_epochs out of range")]
    EpochCount,
    /// `first_epoch` is in the past, or the last epoch is beyond current + 3.
    #[error("session epochs out of range")]
    Epochs,
    /// `x25519_pub` is a low-order point.
    #[error("x25519_pub is a low-order point")]
    LowOrderKey,
    /// `x25519_pub` is used by another session, open or closed.
    #[error("x25519_pub reused")]
    KeyReused,
    /// `bond < max(CHN_SESSION_BOND_MIN, CHN_BOND_PER_MSGRATE × max_msgs_per_s)`.
    #[error("bond too small")]
    BondTooSmall,
    /// The free balance does not cover bond plus fee.
    #[error("free balance does not cover bond and fee")]
    Funds,
}

/// What the checks read from the state after the parent chain block.
pub trait SessionState {
    /// The current epoch.
    fn current_epoch(&self) -> Epoch;
    /// Whether any session, open or closed, already uses `key`.
    fn x25519_used(&self, key: &[u8; 32]) -> bool;
    /// The account's free USDC balance in micro-units.
    fn free_usdc(&self, account: AccountId) -> u128;
}

impl SessionOpen {
    /// The bytes (see the module's encoding gap).
    pub fn encode(&self) -> Vec<u8> {
        let n = self.anchors.len();
        let mut w = Writer::with_capacity(FIXED_LEN.saturating_add(n.saturating_mul(160)));
        w.u32(self.account.0);
        w.u16(self.book_group);
        w.bytes(&self.x25519_pub);
        w.bytes(&self.sign_pub);
        w.u8(self.bound_addr.family);
        w.bytes(&self.bound_addr.ip);
        w.u16(self.bound_addr.port);
        w.u64(self.bond);
        w.u32(self.max_msgs_per_s);
        w.u32(self.first_epoch.0);
        w.u8(u8::try_from(n).unwrap_or(u8::MAX));
        for row in &self.anchors {
            for a in row {
                w.bytes(&a.0);
            }
        }
        w.finish()
    }

    /// The inverse of [`Self::encode`]; rejects `n_epochs` ∉ 1 ..= 3 and trailing bytes.
    pub fn decode(b: &[u8]) -> Result<Self, OpenReject> {
        let mut r = Reader::new(b);
        let m = OpenReject::Malformed;
        let account = AccountId(r.u32().ok_or(m)?);
        let book_group = r.u16().ok_or(m)?;
        let x25519_pub = r.array().ok_or(m)?;
        let sign_pub = r.array().ok_or(m)?;
        let bound_addr = BoundAddr {
            family: r.u8().ok_or(m)?,
            ip: r.array().ok_or(m)?,
            port: r.u16().ok_or(m)?,
        };
        let bond = r.u64().ok_or(m)?;
        let max_msgs_per_s = r.u32().ok_or(m)?;
        let first_epoch = Epoch(r.u32().ok_or(m)?);
        let n = r.u8().ok_or(m)?;
        if !(1..=SESSION_MAX_EPOCHS).contains(&n) {
            return Err(OpenReject::EpochCount);
        }
        let mut anchors = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            let mut row = [Hash::default(); COMMITTEE];
            for a in &mut row {
                *a = Hash(r.array().ok_or(m)?);
            }
            anchors.push(row);
        }
        r.finish().ok_or(m)?;
        Ok(Self {
            account,
            book_group,
            x25519_pub,
            sign_pub,
            bound_addr,
            bond,
            max_msgs_per_s,
            first_epoch,
            anchors,
        })
    }

    /// The last epoch the session covers; it expires at its end. `None` when `n_epochs` is 0.
    pub fn last_epoch(&self) -> Option<Epoch> {
        let n = u32::try_from(self.anchors.len()).ok()?.checked_sub(1)?;
        self.first_epoch.0.checked_add(n).map(Epoch)
    }

    /// `A(e, s)`, if the session covers `e` and `s` is an operator.
    pub fn anchor(&self, e: Epoch, s: u8) -> Option<Hash> {
        let k = usize::try_from(e.0.checked_sub(self.first_epoch.0)?).ok()?;
        self.anchors.get(k)?.get(usize::from(s)).copied()
    }

    /// `BLAKE3(anchors)` over the encoded anchors, for the `SessionLeaf` (09 §9.3).
    pub fn anchors_hash(&self) -> Hash {
        let mut m = Vec::with_capacity(self.anchors.len().saturating_mul(160));
        for a in self.anchors.iter().flatten() {
            m.extend_from_slice(&a.0);
        }
        hash(&m)
    }

    /// The smallest valid bond: `max(CHN_SESSION_BOND_MIN, CHN_BOND_PER_MSGRATE × max_msgs_per_s)`.
    pub fn min_bond(&self) -> u64 {
        // u32 × 10⁴ < 2⁴⁶: never overflows u64.
        BOND_PER_MSGRATE
            .saturating_mul(u64::from(self.max_msgs_per_s))
            .max(SESSION_BOND_MIN)
    }

    /// Checks 2–4 of 09 §5.2, in that order, with `fee` the session item fee in micro-units.
    pub fn check(&self, st: &impl SessionState, fee: u64) -> Result<(), OpenReject> {
        let n = u8::try_from(self.anchors.len()).map_err(|_| OpenReject::EpochCount)?;
        if !(1..=SESSION_MAX_EPOCHS).contains(&n) {
            return Err(OpenReject::EpochCount);
        }
        let cur = st.current_epoch().0;
        let last = self.last_epoch().ok_or(OpenReject::Epochs)?.0;
        if self.first_epoch.0 < cur
            || u64::from(last) > u64::from(cur) + u64::from(SESSION_LEAD_EPOCHS)
        {
            return Err(OpenReject::Epochs);
        }
        if is_low_order(&self.x25519_pub) {
            return Err(OpenReject::LowOrderKey);
        }
        if st.x25519_used(&self.x25519_pub) {
            return Err(OpenReject::KeyReused);
        }
        if self.bond < self.min_bond() {
            return Err(OpenReject::BondTooSmall);
        }
        let need = u128::from(self.bond).saturating_add(u128::from(fee));
        if st.free_usdc(self.account) < need {
            return Err(OpenReject::Funds);
        }
        Ok(())
    }
}

/// Whether `u` is a low-order Montgomery point. X25519 clamps every scalar to a multiple of 8, so
/// any scalar maps a point of order dividing 8 to u = 0, and no other point there.
pub fn is_low_order(u: &[u8; 32]) -> bool {
    x25519::shared_secret(&[1; 32], u).is_none()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    struct St {
        epoch: u32,
        used: Vec<[u8; 32]>,
        free: u128,
    }
    impl SessionState for St {
        fn current_epoch(&self) -> Epoch {
            Epoch(self.epoch)
        }
        fn x25519_used(&self, key: &[u8; 32]) -> bool {
            self.used.contains(key)
        }
        fn free_usdc(&self, _: AccountId) -> u128 {
            self.free
        }
    }

    fn open(n: usize) -> SessionOpen {
        SessionOpen {
            account: AccountId(0x0102_0304),
            book_group: 7,
            x25519_pub: x25519::public_key(&[4; 32]),
            sign_pub: [5; 32],
            bound_addr: BoundAddr {
                family: 6,
                ip: [9; 16],
                port: 0xabcd,
            },
            bond: SESSION_BOND_MIN,
            max_msgs_per_s: 1_000,
            first_epoch: Epoch(10),
            anchors: (0..n)
                .map(|k| core::array::from_fn(|s| Hash([(k * 5 + s) as u8; 32])))
                .collect(),
        }
    }

    fn st() -> St {
        St {
            epoch: 10,
            used: vec![],
            free: u128::from(SESSION_BOND_MIN) + 1_000_000,
        }
    }

    #[test]
    fn encoding_round_trips_and_is_little_endian_in_field_order() {
        let o = open(2);
        let b = o.encode();
        assert_eq!(b.len(), FIXED_LEN + 2 * 160);
        assert_eq!(&b[..6], &[4, 3, 2, 1, 7, 0]);
        assert_eq!(b[70], 6, "family after the two keys");
        assert_eq!(&b[87..89], &[0xcd, 0xab]);
        assert_eq!(b[105], 2, "n_epochs");
        assert_eq!(SessionOpen::decode(&b), Ok(o.clone()));
        assert_eq!(o.anchor(Epoch(11), 4), Some(Hash([9; 32])));
        assert_eq!(o.anchor(Epoch(12), 0), None);
        assert_eq!(o.anchor(Epoch(9), 0), None);
        assert_eq!(o.last_epoch(), Some(Epoch(11)));
        // Short, long, and n_epochs 0 or 4.
        assert_eq!(
            SessionOpen::decode(&b[..b.len() - 1]),
            Err(OpenReject::Malformed)
        );
        let mut long = b.clone();
        long.push(0);
        assert_eq!(SessionOpen::decode(&long), Err(OpenReject::Malformed));
        for bad in [0u8, 4] {
            let mut x = b.clone();
            x[105] = bad;
            assert_eq!(SessionOpen::decode(&x), Err(OpenReject::EpochCount));
        }
    }

    #[test]
    fn checks_run_in_spec_order_at_their_boundaries() {
        let fee = 1_000_000;
        assert_eq!(open(3).check(&st(), fee), Ok(()));
        // Check 2: e ≥ current, last ≤ current + 3.
        assert_eq!(
            open(1).check(&St { epoch: 11, ..st() }, fee),
            Err(OpenReject::Epochs)
        );
        let o = SessionOpen {
            first_epoch: Epoch(11),
            ..open(3)
        };
        assert_eq!(o.check(&st(), fee), Ok(()), "last = current + 3");
        let o = SessionOpen {
            first_epoch: Epoch(12),
            ..open(3)
        };
        assert_eq!(
            o.check(&st(), fee),
            Err(OpenReject::Epochs),
            "last = current + 4"
        );
        assert_eq!(open(0).check(&st(), fee), Err(OpenReject::EpochCount));
        // Check 3.
        let o = SessionOpen {
            x25519_pub: [0; 32],
            ..open(1)
        };
        assert_eq!(o.check(&st(), fee), Err(OpenReject::LowOrderKey));
        let used = St {
            used: vec![open(1).x25519_pub],
            ..st()
        };
        assert_eq!(open(1).check(&used, fee), Err(OpenReject::KeyReused));
        // Check 4: the rate term wins above 100k msg/s.
        let o = SessionOpen {
            max_msgs_per_s: 100_001,
            ..open(1)
        };
        assert_eq!(o.min_bond(), 1_000_010_000);
        assert_eq!(o.check(&st(), fee), Err(OpenReject::BondTooSmall));
        let o = SessionOpen {
            bond: SESSION_BOND_MIN - 1,
            ..open(1)
        };
        assert_eq!(o.check(&st(), fee), Err(OpenReject::BondTooSmall));
        assert_eq!(open(1).check(&st(), fee + 1), Err(OpenReject::Funds));
    }

    #[test]
    fn low_order_points_are_detected() {
        let mut one = [0u8; 32];
        one[0] = 1;
        // A point of order 8 (libsodium's low-order list).
        let order8: [u8; 32] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        for p in [[0u8; 32], one, order8] {
            assert!(is_low_order(&p));
        }
        assert!(!is_low_order(&x25519::public_key(&[4; 32])));
    }
}
