//! The 16-byte records of 10 §7.5, little-endian.

use vyrn_types::{Epoch, Qty, StepId, StepKind, Tick};

use crate::packet::Feed;

/// Bytes per record (10 §7.3).
pub const REC_BYTES: usize = 16;

/// Order side, as in the order flags of 01 §6.2 (bit 0: 0 buy, 1 sell).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    Buy = 0,
    Sell = 1,
}

impl Side {
    const fn from_bit(b: u8) -> Self {
        if b & 1 == 0 { Side::Buy } else { Side::Sell }
    }

    const fn bit(self) -> u8 {
        self as u8
    }
}

code_enum!(
    /// `MD_DELETE` cause (10 §7.5).
    DeleteCause {
        Cancel = 1,
        Replace = 2,
        Stp = 3,
        AccountKill = 4,
        SessionKill = 5,
        AllocationShrink = 6,
        EpochEnd = 7,
        HaltPurge = 8,
        WindowExit = 9,
    }
);

code_enum!(
    /// `MD_STATUS` state (10 §7.5).
    BookStatus {
        Halted = 0,
        Auction = 1,
        Continuous = 2,
        Closed = 3,
    }
);

code_enum!(
    /// `MD_ATTEST` kind (10 §7.5): two of the four facts of 01 §14.13 item 3.
    AttestKind {
        Final = 2,
        Settled = 3,
    }
);

/// One record of 10 §7.5. Field names follow its table; `oid` is `(lane << 24) | slot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    /// 0x01. `ts_delta` is the order's priority `rx_ts` minus the packet's `ts_base`.
    Add {
        side: Side,
        via_bbo: bool,
        auction: bool,
        ts_delta: u16,
        oid: u32,
        tick: Tick,
        qty: Qty,
    },
    /// 0x02. `qty` is the quantity removed, which is all that was left.
    Delete {
        cause: DeleteCause,
        oid: u32,
        tick: Tick,
        qty: Qty,
    },
    /// 0x03. `qty` is the quantity after the reduce.
    Reduce { oid: u32, tick: Tick, qty: Qty },
    /// 0x0E. Lane-op records after it are ordered after `step` and before `step + 1`.
    Sync { step: StepId },
    /// 0x10.
    Step {
        kind: StepKind,
        n_exec: u16,
        step: StepId,
        taker: u32,
    },
    /// 0x11.
    Exec {
        aggressor: Side,
        ordinal: u16,
        maker: u32,
        tick: Tick,
        qty: Qty,
    },
    /// 0x12.
    Bust { ordinal: u16, step: StepId },
    /// 0x20.
    Status {
        status: BookStatus,
        epoch: Epoch,
        step: StepId,
    },
    /// 0x21.
    Attest {
        kind: AttestKind,
        height_low: u32,
        last_step: StepId,
    },
    /// 0x30. `level` is 0–9; `orders` saturates.
    Level {
        side: Side,
        level: u8,
        empty: bool,
        orders: u16,
        tick: Tick,
        qty: u64,
    },
    /// 0x40.
    Trade {
        aggressor: Side,
        auction: bool,
        ts_delta: u16,
        step_delta: u16,
        ordinal: u16,
        tick: Tick,
        qty: Qty,
    },
    /// 0x41.
    TradeBust {
        step_delta: u16,
        ordinal: u16,
        tick: Tick,
        qty: Qty,
    },
    /// 0x50.
    Stat { stat: u8, second: u32, value: u64 },
    /// 0x60.
    SnapBegin {
        feed: Feed,
        n_records: u32,
        as_of: StepId,
    },
    /// 0x61.
    SnapResume { channel: u8, record: u16, seq: u64 },
    /// 0x62. The first 8 bytes of BLAKE3 of the snapshot body, as bytes.
    SnapEnd { hash8: [u8; 8] },
}

/// Why 16 bytes are not a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Byte 0 is not a code of 10 §7.5.
    UnknownType,
    /// A byte or flag bit that 10 §7.5 fixes at 0 is not 0.
    Reserved,
    /// A coded field (cause, step kind, status, attest kind, level, feed) is out of range.
    BadValue,
}

fn put16(b: &mut [u8; REC_BYTES], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8; REC_BYTES], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8; REC_BYTES], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn get16(b: &[u8; REC_BYTES], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn get32(b: &[u8; REC_BYTES], at: usize) -> u32 {
    let mut a = [0; 4];
    a.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(a)
}

fn get64(b: &[u8; REC_BYTES], at: usize) -> u64 {
    let mut a = [0; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// `Err(Reserved)` unless `b[range]` is all zero.
fn zero(b: &[u8; REC_BYTES], range: core::ops::Range<usize>) -> Result<(), RecordError> {
    if b[range].iter().all(|&x| x == 0) {
        Ok(())
    } else {
        Err(RecordError::Reserved)
    }
}

/// `Err(Reserved)` if `flags` has a bit outside `allowed`.
fn bits(flags: u8, allowed: u8) -> Result<(), RecordError> {
    if flags & !allowed == 0 {
        Ok(())
    } else {
        Err(RecordError::Reserved)
    }
}

impl Record {
    /// Byte 0 (10 §7.5).
    pub const fn type_code(&self) -> u8 {
        match self {
            Record::Add { .. } => 0x01,
            Record::Delete { .. } => 0x02,
            Record::Reduce { .. } => 0x03,
            Record::Sync { .. } => 0x0E,
            Record::Step { .. } => 0x10,
            Record::Exec { .. } => 0x11,
            Record::Bust { .. } => 0x12,
            Record::Status { .. } => 0x20,
            Record::Attest { .. } => 0x21,
            Record::Level { .. } => 0x30,
            Record::Trade { .. } => 0x40,
            Record::TradeBust { .. } => 0x41,
            Record::Stat { .. } => 0x50,
            Record::SnapBegin { .. } => 0x60,
            Record::SnapResume { .. } => 0x61,
            Record::SnapEnd { .. } => 0x62,
        }
    }

    pub fn encode(&self) -> [u8; REC_BYTES] {
        let mut b = [0u8; REC_BYTES];
        b[0] = self.type_code();
        match *self {
            Record::Add {
                side,
                via_bbo,
                auction,
                ts_delta,
                oid,
                tick,
                qty,
            } => {
                b[1] = side.bit() | (u8::from(via_bbo) << 1) | (u8::from(auction) << 2);
                put16(&mut b, 2, ts_delta);
                put32(&mut b, 4, oid);
                put32(&mut b, 8, tick.0);
                put32(&mut b, 12, qty.0);
            }
            Record::Delete {
                cause,
                oid,
                tick,
                qty,
            } => {
                b[1] = cause.code();
                put32(&mut b, 4, oid);
                put32(&mut b, 8, tick.0);
                put32(&mut b, 12, qty.0);
            }
            Record::Reduce { oid, tick, qty } => {
                put32(&mut b, 4, oid);
                put32(&mut b, 8, tick.0);
                put32(&mut b, 12, qty.0);
            }
            Record::Sync { step } => put64(&mut b, 8, step.0),
            Record::Step {
                kind,
                n_exec,
                step,
                taker,
            } => {
                b[1] = kind.code();
                put16(&mut b, 2, n_exec);
                put64(&mut b, 4, step.0);
                put32(&mut b, 12, taker);
            }
            Record::Exec {
                aggressor,
                ordinal,
                maker,
                tick,
                qty,
            } => {
                b[1] = aggressor.bit();
                put16(&mut b, 2, ordinal);
                put32(&mut b, 4, maker);
                put32(&mut b, 8, tick.0);
                put32(&mut b, 12, qty.0);
            }
            Record::Bust { ordinal, step } => {
                put16(&mut b, 2, ordinal);
                put64(&mut b, 8, step.0);
            }
            Record::Status {
                status,
                epoch,
                step,
            } => {
                b[1] = status.code();
                put32(&mut b, 4, epoch.0);
                put64(&mut b, 8, step.0);
            }
            Record::Attest {
                kind,
                height_low,
                last_step,
            } => {
                b[1] = kind.code();
                put32(&mut b, 4, height_low);
                put64(&mut b, 8, last_step.0);
            }
            Record::Level {
                side,
                level,
                empty,
                orders,
                tick,
                qty,
            } => {
                b[1] = side.bit() | ((level & 0xF) << 1) | (u8::from(empty) << 5);
                put16(&mut b, 2, orders);
                put32(&mut b, 4, tick.0);
                put64(&mut b, 8, qty);
            }
            Record::Trade {
                aggressor,
                auction,
                ts_delta,
                step_delta,
                ordinal,
                tick,
                qty,
            } => {
                b[1] = aggressor.bit() | (u8::from(auction) << 1);
                put16(&mut b, 2, ts_delta);
                put16(&mut b, 4, step_delta);
                put16(&mut b, 6, ordinal);
                put32(&mut b, 8, tick.0);
                put32(&mut b, 12, qty.0);
            }
            Record::TradeBust {
                step_delta,
                ordinal,
                tick,
                qty,
            } => {
                put16(&mut b, 4, step_delta);
                put16(&mut b, 6, ordinal);
                put32(&mut b, 8, tick.0);
                put32(&mut b, 12, qty.0);
            }
            Record::Stat {
                stat,
                second,
                value,
            } => {
                b[1] = stat;
                put32(&mut b, 4, second);
                put64(&mut b, 8, value);
            }
            Record::SnapBegin {
                feed,
                n_records,
                as_of,
            } => {
                b[1] = feed.code();
                put32(&mut b, 4, n_records);
                put64(&mut b, 8, as_of.0);
            }
            Record::SnapResume {
                channel,
                record,
                seq,
            } => {
                b[1] = channel;
                put16(&mut b, 2, record);
                put64(&mut b, 8, seq);
            }
            Record::SnapEnd { hash8 } => b[8..16].copy_from_slice(&hash8),
        }
        b
    }

    pub fn decode(b: &[u8; REC_BYTES]) -> Result<Self, RecordError> {
        use RecordError::BadValue;
        let f = b[1];
        let tick32 = |at| Tick(get32(b, at));
        let qty32 = |at| Qty(get32(b, at));
        Ok(match b[0] {
            0x01 => {
                bits(f, 0b111)?;
                Record::Add {
                    side: Side::from_bit(f),
                    via_bbo: f & 2 != 0,
                    auction: f & 4 != 0,
                    ts_delta: get16(b, 2),
                    oid: get32(b, 4),
                    tick: tick32(8),
                    qty: qty32(12),
                }
            }
            0x02 => {
                zero(b, 2..4)?;
                Record::Delete {
                    cause: DeleteCause::from_code(f).ok_or(BadValue)?,
                    oid: get32(b, 4),
                    tick: tick32(8),
                    qty: qty32(12),
                }
            }
            0x03 => {
                zero(b, 1..4)?;
                Record::Reduce {
                    oid: get32(b, 4),
                    tick: tick32(8),
                    qty: qty32(12),
                }
            }
            0x0E => {
                zero(b, 1..8)?;
                Record::Sync {
                    step: StepId(get64(b, 8)),
                }
            }
            0x10 => Record::Step {
                kind: StepKind::from_code(f).ok_or(BadValue)?,
                n_exec: get16(b, 2),
                step: StepId(get64(b, 4)),
                taker: get32(b, 12),
            },
            0x11 => {
                bits(f, 1)?;
                Record::Exec {
                    aggressor: Side::from_bit(f),
                    ordinal: get16(b, 2),
                    maker: get32(b, 4),
                    tick: tick32(8),
                    qty: qty32(12),
                }
            }
            0x12 => {
                zero(b, 1..2)?;
                zero(b, 4..8)?;
                Record::Bust {
                    ordinal: get16(b, 2),
                    step: StepId(get64(b, 8)),
                }
            }
            0x20 => {
                zero(b, 2..4)?;
                Record::Status {
                    status: BookStatus::from_code(f).ok_or(BadValue)?,
                    epoch: Epoch(get32(b, 4)),
                    step: StepId(get64(b, 8)),
                }
            }
            0x21 => {
                zero(b, 2..4)?;
                Record::Attest {
                    kind: AttestKind::from_code(f).ok_or(BadValue)?,
                    height_low: get32(b, 4),
                    last_step: StepId(get64(b, 8)),
                }
            }
            0x30 => {
                bits(f, 0b11_1111)?;
                let level = (f >> 1) & 0xF;
                if level > 9 {
                    return Err(BadValue);
                }
                Record::Level {
                    side: Side::from_bit(f),
                    level,
                    empty: f & 0x20 != 0,
                    orders: get16(b, 2),
                    tick: tick32(4),
                    qty: get64(b, 8),
                }
            }
            0x40 => {
                bits(f, 0b11)?;
                Record::Trade {
                    aggressor: Side::from_bit(f),
                    auction: f & 2 != 0,
                    ts_delta: get16(b, 2),
                    step_delta: get16(b, 4),
                    ordinal: get16(b, 6),
                    tick: tick32(8),
                    qty: qty32(12),
                }
            }
            0x41 => {
                zero(b, 1..4)?;
                Record::TradeBust {
                    step_delta: get16(b, 4),
                    ordinal: get16(b, 6),
                    tick: tick32(8),
                    qty: qty32(12),
                }
            }
            0x50 => {
                zero(b, 2..4)?;
                Record::Stat {
                    stat: f,
                    second: get32(b, 4),
                    value: get64(b, 8),
                }
            }
            0x60 => {
                zero(b, 2..4)?;
                Record::SnapBegin {
                    feed: Feed::from_code(f).ok_or(BadValue)?,
                    n_records: get32(b, 4),
                    as_of: StepId(get64(b, 8)),
                }
            }
            0x61 => {
                zero(b, 4..8)?;
                Record::SnapResume {
                    channel: f,
                    record: get16(b, 2),
                    seq: get64(b, 8),
                }
            }
            0x62 => {
                zero(b, 1..8)?;
                let mut hash8 = [0; 8];
                hash8.copy_from_slice(&b[8..16]);
                Record::SnapEnd { hash8 }
            }
            _ => return Err(RecordError::UnknownType),
        })
    }
}
