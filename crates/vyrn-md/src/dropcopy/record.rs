//! The 48-byte drop-copy record (10 §8.1) and the `DC_EOD` layout (10 §8.4 item 6).

use vyrn_types::{AccountId, Handle, Height, Qty, SessionId, StepId, Tick};

use crate::record::Side;

/// Bytes of one record.
pub const DC_REC_BYTES: usize = 48;

/// `flags` bit 0: the order's side is sell.
pub const DC_SELL: u8 = 1;
/// `flags` bit 1: the account was the taker.
pub const DC_TAKER: u8 = 2;
/// `flags` bit 2: durable. Always set: the observer sends only what it holds from both
/// replication paths (10 §8.2).
pub const DC_DURABLE: u8 = 4;

/// `type` (10 §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DcType {
    Fill = 1,
    Ack = 2,
    Cancel = 3,
    Out = 4,
    Alloc = 5,
    Final = 6,
    Revert = 7,
    Eod = 8,
    Settled = 9,
    Route = 10,
}

impl DcType {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => Self::Fill,
            2 => Self::Ack,
            3 => Self::Cancel,
            4 => Self::Out,
            5 => Self::Alloc,
            6 => Self::Final,
            7 => Self::Revert,
            8 => Self::Eod,
            9 => Self::Settled,
            10 => Self::Route,
            _ => return None,
        })
    }

    /// `DC_FINAL` and `DC_SETTLED` mark stages; they are not canonical records (10 §8.4 item 3).
    pub const fn is_stage(self) -> bool {
        matches!(self, Self::Final | Self::Settled)
    }
}

/// Why a record does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcRecordError {
    Type(u8),
    /// Flag bits 3–7, or bit 2 clear.
    Flags(u8),
}

/// One drop-copy record, as its 48 bytes (10 §8.1). The named constructors and accessors
/// give the per-type meaning of the shared fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DcRecord(pub [u8; DC_REC_BYTES]);

/// The fields of an execution or order record (`DC_FILL`, `DC_ACK`, `DC_CANCEL`, `DC_OUT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcOrder {
    pub kind: DcType,
    pub side: Side,
    pub taker: bool,
    pub ordinal: u16,
    pub account: AccountId,
    /// `StepId` for `DC_FILL` and a step's `DC_OUT`; else the lane op's `LaneSeq`.
    pub step: u64,
    pub session: SessionId,
    pub resp_seq: u32,
    pub handle: Handle,
    pub tick: Tick,
    pub qty: Qty,
    pub client_tag: u32,
    pub fee: i64,
}

/// `DC_EOD` ordinal 0: totals (10 §8.4 item 6).
pub const EOD_TOTALS: u16 = 0;
/// `DC_EOD` ordinal 1: fees.
pub const EOD_FEES: u16 = 1;
/// `DC_EOD` ordinal 2: closing balances.
pub const EOD_BALANCES: u16 = 2;
/// `DC_EOD` ordinal 3: the stream hash; the last record of a stream's epoch.
pub const EOD_HASH: u16 = 3;

impl DcRecord {
    pub fn order(o: &DcOrder) -> Self {
        let mut b = [0; DC_REC_BYTES];
        b[0] = o.kind.code();
        let side = match o.side {
            Side::Buy => 0,
            Side::Sell => DC_SELL,
        };
        b[1] = side | if o.taker { DC_TAKER } else { 0 } | DC_DURABLE;
        b[2..4].copy_from_slice(&o.ordinal.to_le_bytes());
        b[4..8].copy_from_slice(&o.account.0.to_le_bytes());
        b[8..16].copy_from_slice(&o.step.to_le_bytes());
        b[16..20].copy_from_slice(&o.session.0.to_le_bytes());
        b[20..24].copy_from_slice(&o.resp_seq.to_le_bytes());
        b[24..28].copy_from_slice(&o.handle.0.to_le_bytes());
        b[28..32].copy_from_slice(&o.tick.0.to_le_bytes());
        b[32..36].copy_from_slice(&o.qty.0.to_le_bytes());
        b[36..40].copy_from_slice(&o.client_tag.to_le_bytes());
        b[40..48].copy_from_slice(&o.fee.to_le_bytes());
        Self(b)
    }

    /// `DC_FINAL` or `DC_SETTLED`: every earlier record of the stream up to `step` is at this
    /// stage, as of block `height` (10 §8.1).
    pub fn stage(kind: DcType, account: AccountId, step: StepId, height: Height) -> Self {
        let mut b = [0; DC_REC_BYTES];
        b[0] = kind.code();
        b[1] = DC_DURABLE;
        b[4..8].copy_from_slice(&account.0.to_le_bytes());
        b[8..16].copy_from_slice(&step.0.to_le_bytes());
        b[24..32].copy_from_slice(&height.0.to_le_bytes());
        Self(b)
    }

    /// `DC_EOD` with `ordinal` and five 8-byte words at bytes 8–47.
    pub fn eod(account: AccountId, ordinal: u16, words: [u64; 5]) -> Self {
        let mut b = [0; DC_REC_BYTES];
        b[0] = DcType::Eod.code();
        b[1] = DC_DURABLE;
        b[2..4].copy_from_slice(&ordinal.to_le_bytes());
        b[4..8].copy_from_slice(&account.0.to_le_bytes());
        for (i, w) in words.iter().enumerate() {
            let at = 8 + 8 * i;
            b[at..at + 8].copy_from_slice(&w.to_le_bytes());
        }
        Self(b)
    }

    /// The last `DC_EOD`: `n` records hashed, then their BLAKE3 hash.
    pub fn eod_hash(account: AccountId, n: u64, hash: &[u8; 32]) -> Self {
        let mut r = Self::eod(account, EOD_HASH, [n, 0, 0, 0, 0]);
        r.0[16..48].copy_from_slice(hash);
        r
    }

    pub fn decode(b: &[u8; DC_REC_BYTES]) -> Result<Self, DcRecordError> {
        DcType::from_code(b[0]).ok_or(DcRecordError::Type(b[0]))?;
        if b[1] & !(DC_SELL | DC_TAKER | DC_DURABLE) != 0 || b[1] & DC_DURABLE == 0 {
            return Err(DcRecordError::Flags(b[1]));
        }
        Ok(Self(*b))
    }

    pub fn kind(&self) -> DcType {
        // Every constructor and `decode` write a valid code.
        DcType::from_code(self.0[0]).unwrap_or(DcType::Alloc)
    }

    pub fn ordinal(&self) -> u16 {
        u16::from_le_bytes([self.0[2], self.0[3]])
    }

    pub fn account(&self) -> AccountId {
        AccountId(self.u32_at(4))
    }

    pub fn step(&self) -> u64 {
        self.u64_at(8)
    }

    pub fn session(&self) -> SessionId {
        SessionId(self.u32_at(16))
    }

    pub fn resp_seq(&self) -> u32 {
        self.u32_at(20)
    }

    pub fn handle(&self) -> Handle {
        Handle(self.u32_at(24))
    }

    pub fn tick(&self) -> Tick {
        Tick(self.u32_at(28))
    }

    pub fn qty(&self) -> Qty {
        Qty(self.u32_at(32))
    }

    pub fn client_tag(&self) -> u32 {
        self.u32_at(36)
    }

    pub fn fee(&self) -> i64 {
        i64::from_le_bytes(self.arr(40))
    }

    /// `DC_FINAL` / `DC_SETTLED`: the block height at bytes 24–31.
    pub fn height(&self) -> Height {
        Height(self.u64_at(24))
    }

    pub fn side(&self) -> Side {
        if self.0[1] & DC_SELL == 0 {
            Side::Buy
        } else {
            Side::Sell
        }
    }

    pub fn taker(&self) -> bool {
        self.0[1] & DC_TAKER != 0
    }

    /// `DC_EOD` word `i` (0–4) at bytes `8 + 8i`.
    pub fn word(&self, i: usize) -> u64 {
        self.u64_at(8 + 8 * i.min(4))
    }

    /// The hash of a hash `DC_EOD` (bytes 16–47).
    pub fn hash(&self) -> [u8; 32] {
        let mut h = [0; 32];
        h.copy_from_slice(&self.0[16..48]);
        h
    }

    fn arr(&self, at: usize) -> [u8; 8] {
        let mut a = [0; 8];
        a.copy_from_slice(&self.0[at..at + 8]);
        a
    }

    fn u64_at(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.arr(at))
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes([self.0[at], self.0[at + 1], self.0[at + 2], self.0[at + 3]])
    }
}
