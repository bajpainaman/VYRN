//! Packets and records of 01 §6.1-6.5, and the RxRing/TxRing traits.
//!
//! Parsing uses `zerocopy` layouts, so it needs no `unsafe`. Every parse returns a `Result` whose
//! error is a 01 §6.5 reason with its 04 §11 detail. Nothing here panics on input bytes.
#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::as_conversions)]

mod msg;
mod packet;
mod raw;
mod record;
mod session;

pub use msg::{Msg, OrderFlags, Side, Stp, Tif};
pub use packet::{
    MAX_RECS_PER_PKT, PROTO_RESP_MAX_BYTES, ReqHeader, Request, RespHeader, Response,
    encode_request, encode_response,
};
pub use raw::RawRec;
pub use record::{AttestLevel, Liq, OutCause, Record};
pub use session::{session_generation, session_id, session_lane, session_slot};

use vyrn_types::RejectReason;

/// `CancelAck.handle` of a `CancelAll` summary (04 §6.7). Never a real handle.
pub const PROTO_HANDLE_ALL: u32 = 0xFFFF_FFFF;
/// `index` of a record that answers a packet or the session, not one message.
pub const INDEX_NONE: u8 = 0xFF;

/// `BAD_TYPE` details (04 §11).
pub const PROTO_D_UNKNOWN_TYPE: u32 = 1;
pub const PROTO_D_RESERVED: u32 = 2;
pub const PROTO_D_FLAGS: u32 = 3;
pub const PROTO_D_BAD_HDR: u32 = 4;

/// Why bytes did not parse: the reject reason and detail the receiver reports (01 §6.5, 04 §8).
///
/// A request whose length or `count` is wrong (04 §3.1 V1) is dropped without a response; it
/// still parses to `BAD_TYPE` / `PROTO_D_BAD_HDR` so that callers have one error type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireError {
    pub reason: RejectReason,
    pub detail: u32,
}

impl WireError {
    pub const fn bad_type(detail: u32) -> Self {
        Self {
            reason: RejectReason::BadType,
            detail,
        }
    }
}
