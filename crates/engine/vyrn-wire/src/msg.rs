//! Request messages (01 §6.2) and the layout checks M2 and M3 of 04 §3.3.

use vyrn_types::{Handle, Qty, Tick};

use crate::raw::RawRec;
use crate::{PROTO_D_FLAGS, PROTO_D_RESERVED, PROTO_D_UNKNOWN_TYPE, WireError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Buy,
    Sell,
}

/// Time in force, order flags bits 1–2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tif {
    Day,
    Ioc,
    Fok,
    AuctionOnly,
}

/// Self-trade prevention, order flags bits 4–5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stp {
    None,
    CancelNewest,
    CancelOldest,
    CancelBoth,
}

/// The order flags byte of `New` and `Replace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderFlags {
    pub side: Side,
    pub tif: Tif,
    pub post_only: bool,
    pub stp: Stp,
}

impl OrderFlags {
    /// Bits 6–7 set: `PROTO_D_RESERVED`. Post-only with `IOC`, `FOK` or `AUCTION_ONLY`:
    /// `PROTO_D_FLAGS` (04 §6.1).
    pub fn from_byte(b: u8) -> Result<Self, WireError> {
        if b & 0xC0 != 0 {
            return Err(WireError::bad_type(PROTO_D_RESERVED));
        }
        let side = if b & 1 == 0 { Side::Buy } else { Side::Sell };
        let tif = match (b >> 1) & 3 {
            0 => Tif::Day,
            1 => Tif::Ioc,
            2 => Tif::Fok,
            _ => Tif::AuctionOnly,
        };
        let post_only = b & 0x08 != 0;
        let stp = match (b >> 4) & 3 {
            0 => Stp::None,
            1 => Stp::CancelNewest,
            2 => Stp::CancelOldest,
            _ => Stp::CancelBoth,
        };
        if post_only && tif != Tif::Day {
            return Err(WireError::bad_type(PROTO_D_FLAGS));
        }
        Ok(Self {
            side,
            tif,
            post_only,
            stp,
        })
    }

    pub fn to_byte(self) -> u8 {
        let side = match self.side {
            Side::Buy => 0,
            Side::Sell => 1,
        };
        let tif = match self.tif {
            Tif::Day => 0,
            Tif::Ioc => 1,
            Tif::Fok => 2,
            Tif::AuctionOnly => 3,
        };
        let stp = match self.stp {
            Stp::None => 0,
            Stp::CancelNewest => 1,
            Stp::CancelOldest => 2,
            Stp::CancelBoth => 3,
        };
        side | tif << 1 | u8::from(self.post_only) << 3 | stp << 4
    }
}

/// One request message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Msg {
    New {
        flags: OrderFlags,
        tick: Tick,
        qty: Qty,
        client_tag: u32,
    },
    Cancel {
        handle: Handle,
        client_tag: u32,
    },
    Reduce {
        handle: Handle,
        by: Qty,
        client_tag: u32,
    },
    /// Carries no `client_tag`: the order keeps its stored tag (04 §6.5).
    Replace {
        flags: OrderFlags,
        handle: Handle,
        tick: Tick,
        qty: Qty,
    },
    Heartbeat,
    ResendReq {
        from: u32,
        to: u32,
    },
    CancelAll {
        client_tag: u32,
    },
}

impl Msg {
    pub const NEW: u8 = 0x01;
    pub const CANCEL: u8 = 0x02;
    pub const REDUCE: u8 = 0x03;
    pub const REPLACE: u8 = 0x04;
    pub const HEARTBEAT: u8 = 0x10;
    pub const RESEND_REQ: u8 = 0x11;
    pub const CANCEL_ALL: u8 = 0x12;

    /// M2 (type is defined), then M3 (every 0 field is 0, flags valid).
    pub fn decode(bytes: &[u8; 16]) -> Result<Self, WireError> {
        let r = RawRec::from_array(bytes);
        let (a, b, c) = (r.a.get(), r.b.get(), r.c.get());
        // Which fields the layout marks 0: (flags byte, bytes 2–3, 4–7, 8–11, 12–15).
        let zero = match r.kind {
            Self::NEW => [false, true, false, false, false],
            Self::CANCEL => [true, true, false, true, false],
            Self::REDUCE => [true, true, false, false, false],
            Self::REPLACE => [false, true, false, false, false],
            Self::HEARTBEAT => [true, true, true, true, true],
            Self::RESEND_REQ => [true, true, false, false, true],
            Self::CANCEL_ALL => [true, true, true, true, false],
            _ => return Err(WireError::bad_type(PROTO_D_UNKNOWN_TYPE)),
        };
        let fields = [u32::from(r.b1), u32::from(r.w.get()), a, b, c];
        if zero.iter().zip(fields).any(|(&z, v)| z && v != 0) {
            return Err(WireError::bad_type(PROTO_D_RESERVED));
        }
        Ok(match r.kind {
            Self::NEW => Self::New {
                flags: OrderFlags::from_byte(r.b1)?,
                tick: Tick(a),
                qty: Qty(b),
                client_tag: c,
            },
            Self::CANCEL => Self::Cancel {
                handle: Handle(a),
                client_tag: c,
            },
            Self::REDUCE => Self::Reduce {
                handle: Handle(a),
                by: Qty(b),
                client_tag: c,
            },
            Self::REPLACE => Self::Replace {
                flags: OrderFlags::from_byte(r.b1)?,
                handle: Handle(a),
                tick: Tick(b),
                qty: Qty(c),
            },
            Self::HEARTBEAT => Self::Heartbeat,
            Self::RESEND_REQ => Self::ResendReq { from: a, to: b },
            _ => Self::CancelAll { client_tag: c },
        })
    }

    pub fn raw(self) -> RawRec {
        match self {
            Self::New {
                flags,
                tick,
                qty,
                client_tag,
            } => RawRec::new(Self::NEW, flags.to_byte(), 0, tick.0, qty.0, client_tag),
            Self::Cancel { handle, client_tag } => {
                RawRec::new(Self::CANCEL, 0, 0, handle.0, 0, client_tag)
            }
            Self::Reduce {
                handle,
                by,
                client_tag,
            } => RawRec::new(Self::REDUCE, 0, 0, handle.0, by.0, client_tag),
            Self::Replace {
                flags,
                handle,
                tick,
                qty,
            } => RawRec::new(Self::REPLACE, flags.to_byte(), 0, handle.0, tick.0, qty.0),
            Self::Heartbeat => RawRec::new(Self::HEARTBEAT, 0, 0, 0, 0, 0),
            Self::ResendReq { from, to } => RawRec::new(Self::RESEND_REQ, 0, 0, from, to, 0),
            Self::CancelAll { client_tag } => RawRec::new(Self::CANCEL_ALL, 0, 0, 0, 0, client_tag),
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
    fn flags_reject_reserved_bits_and_bad_combinations() {
        assert_eq!(
            OrderFlags::from_byte(0x40),
            Err(WireError::bad_type(PROTO_D_RESERVED))
        );
        assert_eq!(
            OrderFlags::from_byte(0x80),
            Err(WireError::bad_type(PROTO_D_RESERVED))
        );
        // Post-only is allowed with Day only.
        assert!(OrderFlags::from_byte(0x08).is_ok());
        for tif in 1..=3u8 {
            assert_eq!(
                OrderFlags::from_byte(0x08 | tif << 1),
                Err(WireError::bad_type(PROTO_D_FLAGS))
            );
        }
        for b in 0..0x40u8 {
            if let Ok(f) = OrderFlags::from_byte(b) {
                assert_eq!(f.to_byte(), b);
            }
        }
    }

    #[test]
    fn every_zero_field_is_checked() {
        // A Cancel with a nonzero qty field, a Heartbeat with a nonzero tag, a CancelAll with flags.
        let mut cancel = Msg::Cancel {
            handle: Handle(1),
            client_tag: 2,
        }
        .encode();
        cancel[8] = 1;
        let mut hb = Msg::Heartbeat.encode();
        hb[15] = 1;
        let mut ca = Msg::CancelAll { client_tag: 3 }.encode();
        ca[1] = 1;
        let mut new = Msg::Heartbeat.encode();
        new[0] = Msg::NEW;
        new[2] = 1;
        for bad in [cancel, hb, ca, new] {
            assert_eq!(
                Msg::decode(&bad),
                Err(WireError::bad_type(PROTO_D_RESERVED))
            );
        }
        let mut unknown = Msg::Heartbeat.encode();
        unknown[0] = 0x05;
        assert_eq!(
            Msg::decode(&unknown),
            Err(WireError::bad_type(PROTO_D_UNKNOWN_TYPE))
        );
    }
}
