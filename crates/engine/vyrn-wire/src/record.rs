//! Response records (01 §6.4, §14.10; 04 §7; 09 §17.2).

use vyrn_types::{Epoch, Handle, MAX_MSGS_PER_PKT, Qty, RejectReason, Tick};

use crate::raw::RawRec;
use crate::{INDEX_NONE, PROTO_D_RESERVED, PROTO_D_UNKNOWN_TYPE, WireError};

/// `Fill.liq` and `Bust.liq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Liq {
    Maker,
    Taker,
    Auction,
}

impl Liq {
    fn from_code(w: u16) -> Option<Self> {
        match w {
            0 => Some(Self::Maker),
            1 => Some(Self::Taker),
            2 => Some(Self::Auction),
            _ => None,
        }
    }

    fn code(self) -> u16 {
        match self {
            Self::Maker => 0,
            Self::Taker => 1,
            Self::Auction => 2,
        }
    }
}

/// `Out.cause` (`PROTO_OUT_*`, 04 §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutCause {
    IocRemainder,
    Stp,
    AuctionUnfilled,
    Expired,
    PostOnly,
    LaneMoved,
    Disconnect,
    Admin,
}

impl OutCause {
    const ALL: [Self; 8] = [
        Self::IocRemainder,
        Self::Stp,
        Self::AuctionUnfilled,
        Self::Expired,
        Self::PostOnly,
        Self::LaneMoved,
        Self::Disconnect,
        Self::Admin,
    ];

    pub fn code(self) -> u16 {
        match self {
            Self::IocRemainder => 1,
            Self::Stp => 2,
            Self::AuctionUnfilled => 3,
            Self::Expired => 4,
            Self::PostOnly => 5,
            Self::LaneMoved => 6,
            Self::Disconnect => 7,
            Self::Admin => 8,
        }
    }

    pub fn from_code(c: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.code() == c)
    }
}

/// `Attest.level` (04 §7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestLevel {
    Durable,
    Final,
    Settled,
}

impl AttestLevel {
    fn from_code(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Durable),
            2 => Some(Self::Final),
            3 => Some(Self::Settled),
            _ => None,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Durable => 1,
            Self::Final => 2,
            Self::Settled => 3,
        }
    }
}

/// One response record. `index` is the message index 0–9, or `INDEX_NONE` (0xFF).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    Ack {
        index: u8,
        handle: Handle,
        tick: Tick,
        client_tag: u32,
    },
    Fill {
        index: u8,
        liq: Liq,
        handle: Handle,
        tick: Tick,
        qty: Qty,
    },
    Reject {
        index: u8,
        reason: RejectReason,
        detail: u32,
        client_tag: u32,
    },
    /// `handle` is `PROTO_HANDLE_ALL` and `qty` the order count for a `CancelAll` summary.
    CancelAck {
        index: u8,
        handle: Handle,
        qty: Qty,
        client_tag: u32,
    },
    Out {
        index: u8,
        cause: OutCause,
        handle: Handle,
        qty: Qty,
        client_tag: u32,
    },
    /// `home` is the home word of 04 §7.4 (byte 8 `HomeCode`, byte 9 the box).
    EpochNotice { next: Epoch, home: u32, secs: u32 },
    /// The `Fill` layout with index 0xFF; `qty` is the reversed quantity (09 §17.2).
    Bust {
        liq: Liq,
        handle: Handle,
        tick: Tick,
        qty: Qty,
    },
    /// `height` is the low 32 bits of the block height.
    Attest {
        level: AttestLevel,
        upto: u32,
        height: u32,
    },
}

impl Record {
    pub const ACK: u8 = 0x81;
    pub const FILL: u8 = 0x82;
    pub const REJECT: u8 = 0x83;
    pub const CANCEL_ACK: u8 = 0x84;
    pub const OUT: u8 = 0x85;
    pub const EPOCH_NOTICE: u8 = 0x86;
    pub const BUST: u8 = 0x87;
    pub const ATTEST: u8 = 0x88;

    pub fn decode(bytes: &[u8; 16]) -> Result<Self, WireError> {
        let r = RawRec::from_array(bytes);
        let (i, w, a, b, c) = (r.b1, r.w.get(), r.a.get(), r.b.get(), r.c.get());
        let reserved = || WireError::bad_type(PROTO_D_RESERVED);
        let need = |ok: bool| if ok { Ok(()) } else { Err(reserved()) };
        // Records that answer a message carry its index 0–9, or INDEX_NONE (04 §7).
        if matches!(
            r.kind,
            Self::ACK | Self::FILL | Self::REJECT | Self::CANCEL_ACK | Self::OUT
        ) {
            need(i < MAX_MSGS_PER_PKT || i == INDEX_NONE)?;
        }
        Ok(match r.kind {
            Self::ACK => {
                need(w == 0)?;
                Self::Ack {
                    index: i,
                    handle: Handle(a),
                    tick: Tick(b),
                    client_tag: c,
                }
            }
            Self::FILL => Self::Fill {
                index: i,
                liq: Liq::from_code(w).ok_or_else(reserved)?,
                handle: Handle(a),
                tick: Tick(b),
                qty: Qty(c),
            },
            Self::REJECT => {
                need(b == 0)?;
                let reason = RejectReason::from_code(w).ok_or_else(reserved)?;
                Self::Reject {
                    index: i,
                    reason,
                    detail: a,
                    client_tag: c,
                }
            }
            Self::CANCEL_ACK => {
                need(w == 0)?;
                Self::CancelAck {
                    index: i,
                    handle: Handle(a),
                    qty: Qty(b),
                    client_tag: c,
                }
            }
            Self::OUT => Self::Out {
                index: i,
                cause: OutCause::from_code(w).ok_or_else(reserved)?,
                handle: Handle(a),
                qty: Qty(b),
                client_tag: c,
            },
            Self::EPOCH_NOTICE => {
                // Bytes 10–11 of the home word are 0 (04 §7.4).
                need(i == 0 && w == 0 && b >> 16 == 0)?;
                Self::EpochNotice {
                    next: Epoch(a),
                    home: b,
                    secs: c,
                }
            }
            Self::BUST => {
                need(i == INDEX_NONE)?;
                let liq = Liq::from_code(w).ok_or_else(reserved)?;
                Self::Bust {
                    liq,
                    handle: Handle(a),
                    tick: Tick(b),
                    qty: Qty(c),
                }
            }
            Self::ATTEST => {
                need(w == 0 && c == 0)?;
                let level = AttestLevel::from_code(i).ok_or_else(reserved)?;
                Self::Attest {
                    level,
                    upto: a,
                    height: b,
                }
            }
            _ => return Err(WireError::bad_type(PROTO_D_UNKNOWN_TYPE)),
        })
    }

    pub fn raw(self) -> RawRec {
        match self {
            Self::Ack {
                index,
                handle,
                tick,
                client_tag,
            } => RawRec::new(Self::ACK, index, 0, handle.0, tick.0, client_tag),
            Self::Fill {
                index,
                liq,
                handle,
                tick,
                qty,
            } => RawRec::new(Self::FILL, index, liq.code(), handle.0, tick.0, qty.0),
            Self::Reject {
                index,
                reason,
                detail,
                client_tag,
            } => RawRec::new(Self::REJECT, index, reason.code(), detail, 0, client_tag),
            Self::CancelAck {
                index,
                handle,
                qty,
                client_tag,
            } => RawRec::new(Self::CANCEL_ACK, index, 0, handle.0, qty.0, client_tag),
            Self::Out {
                index,
                cause,
                handle,
                qty,
                client_tag,
            } => RawRec::new(Self::OUT, index, cause.code(), handle.0, qty.0, client_tag),
            Self::EpochNotice { next, home, secs } => {
                RawRec::new(Self::EPOCH_NOTICE, 0, 0, next.0, home, secs)
            }
            Self::Bust {
                liq,
                handle,
                tick,
                qty,
            } => RawRec::new(Self::BUST, INDEX_NONE, liq.code(), handle.0, tick.0, qty.0),
            Self::Attest {
                level,
                upto,
                height,
            } => RawRec::new(Self::ATTEST, level.code(), 0, upto, height, 0),
        }
    }

    pub fn encode(self) -> [u8; 16] {
        self.raw().to_array()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_index_is_0_to_9_or_none() {
        let ack = |index| {
            Record::Ack {
                index,
                handle: Handle(1),
                tick: Tick(2),
                client_tag: 3,
            }
            .encode()
        };
        for ok in [0u8, 9, INDEX_NONE] {
            assert!(Record::decode(&ack(ok)).is_ok());
        }
        for bad in [10u8, 0x80, 0xFE] {
            assert_eq!(
                Record::decode(&ack(bad)),
                Err(WireError::bad_type(PROTO_D_RESERVED))
            );
        }
    }

    #[test]
    fn epoch_notice_home_word_bytes_10_11_are_reserved() {
        let ok = Record::EpochNotice {
            next: Epoch(1001),
            home: 2 | 1 << 8,
            secs: 3600,
        }
        .encode();
        assert!(Record::decode(&ok).is_ok());
        let (mut b10, mut b11) = (ok, ok);
        b10[10] = 1;
        b11[11] = 0x80;
        for bad in [b10, b11] {
            assert_eq!(
                Record::decode(&bad),
                Err(WireError::bad_type(PROTO_D_RESERVED))
            );
        }
    }
}
