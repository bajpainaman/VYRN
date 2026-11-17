//! Packets and records of 01 §6.1-6.5, and the RxRing/TxRing traits of 06 §6.1.
//!
//! Parsing uses `zerocopy` layouts, so it needs no `unsafe`. Every parse returns a `Result` whose
//! error is a 01 §6.5 reason with its 04 §14 detail. Nothing here panics on input bytes.
//!
//! # Where each item is specified
//!
//! | Item | Spec |
//! |---|---|
//! | `ReqHeader`, `Request`, `encode_request` | 01 §6.1; checks V1 and V9 of 04 §3.1 |
//! | `Msg`, `OrderFlags`, `Side`, `Tif`, `Stp` | 01 §6.2; checks M2 and M3 of 04 §3.3, flags 04 §6.1 |
//! | `RespHeader`, `Response`, `encode_response`, `MAX_RECS_PER_PKT`, `PROTO_RESP_MAX_BYTES` | 01 §6.3, 04 §1 |
//! | `Record`, `Liq`, `OutCause`, `AttestLevel`, `INDEX_NONE`, `PROTO_HANDLE_ALL` | 01 §6.4 and §14.10, 04 §7, 09 §17.2 |
//! | `WireError`, `PROTO_D_*` | 01 §6.5, 04 §8 and §14 |
//! | `RawRec` | the 16-byte shape shared by 01 §6.2 and §6.4 |
//! | `session_*` | 04 §4.1 |
//! | `ring` | 06 §6.1 |
//!
//! # Versioning
//!
//! This crate implements protocol version `PROTO_VERSION` (04 §12). The wire carries no version
//! field: a session fixes its version when it opens, so no parse here branches on a version. New
//! versions add meaning only in new type codes or in fields that v1 reserves (VR2), which is why
//! every parse refuses a nonzero reserved field or bit (VR1) instead of ignoring it. The byte
//! layouts change only by an edit of 01 §6 (VR5). `tests/golden/README.md` says how an independent
//! implementation checks itself against the conformance vectors.
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
pub mod ring;
mod session;

pub use msg::{Msg, OrderFlags, Side, Stp, Tif};
pub use packet::{
    MAX_RECS_PER_PKT, PROTO_RESP_MAX_BYTES, ReqHeader, Request, RespHeader, Response,
    encode_request, encode_response,
};
pub use raw::RawRec;
pub use record::{AttestLevel, Liq, OutCause, Record};
pub use ring::{NicCounters, RX_BURST, RxFlags, RxPkt, RxRing, TsSource, TxFull, TxRing};
pub use session::{session_generation, session_id, session_lane, session_slot};

use vyrn_types::RejectReason;

/// The protocol version this crate parses and builds: `proto_version` at session open (04 §4.4,
/// §12). Session open, not the packet, carries it.
pub const PROTO_VERSION: u16 = 1;
/// `CancelAck.handle` of a `CancelAll` summary (04 §6.6). Never a real handle.
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
