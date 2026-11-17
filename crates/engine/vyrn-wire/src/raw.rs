//! The 16-byte shape shared by every message (01 §6.2) and response record (01 §6.4).

use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Bytes 0, 1, 2–3, 4–7, 8–11, 12–15 of a message or record, little-endian.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C)]
pub struct RawRec {
    pub kind: u8,
    pub b1: u8,
    pub w: U16,
    pub a: U32,
    pub b: U32,
    pub c: U32,
}
const _: () = assert!(size_of::<RawRec>() == vyrn_types::MSG_BYTES);

impl RawRec {
    pub fn new(kind: u8, b1: u8, w: u16, a: u32, b: u32, c: u32) -> Self {
        Self {
            kind,
            b1,
            w: w.into(),
            a: a.into(),
            b: b.into(),
            c: c.into(),
        }
    }

    pub fn from_array(bytes: &[u8; 16]) -> Self {
        Self::read_from_bytes(bytes).unwrap_or_default()
    }

    pub fn to_array(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(self.as_bytes());
        out
    }
}
