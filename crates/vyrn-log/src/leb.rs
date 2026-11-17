//! LEB128 and ZigZag, the varints of the order stream (07 §3.4–§3.9).
//!
//! # Format
//!
//! **Unsigned LEB128** of a `u64` `v`: emit `v` seven bits at a time, least significant group
//! first. Every byte but the last has bit 7 set. The encoding is the shortest one, so it is 1 to
//! 10 bytes long. Examples: `0` → `00`, `127` → `7F`, `128` → `80 01`, `300` → `AC 02`,
//! `u64::MAX` → `FF FF FF FF FF FF FF FF FF 01`.
//!
//! **ZigZag** maps an `i64` to a `u64` so that small magnitudes stay short:
//! `0 → 0, −1 → 1, 1 → 2, −2 → 3, …`, i.e. `(v << 1) ^ (v >> 63)` with an arithmetic shift.
//! A signed field is the LEB128 of its ZigZag value.
//!
//! **Canonical decoding.** A decoder accepts exactly the bytes the encoder above produces, so
//! that every client reaches the same verdict on every frame (`RepErr::Leb` otherwise):
//!
//! - the last byte of a multi-byte encoding is not `00` (no overlong forms such as `80 00`);
//! - the tenth byte, if reached, is `00` or `01` (no value above `u64::MAX`, no eleventh byte);
//! - a field narrower than 64 bits rejects a value that does not fit it (`RepErr::Range`).

use crate::RepErr;

/// The longest LEB128 encoding of a `u64`.
pub const LEB_MAX_BYTES: usize = 10;

/// Appends the LEB128 encoding of `v`.
pub fn put_u64(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let low = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// Appends the LEB128 encoding of `zigzag(v)`.
pub fn put_i64(out: &mut Vec<u8>, v: i64) {
    put_u64(out, zigzag(v));
}

/// The number of bytes `put_u64(v)` writes.
pub fn len_u64(v: u64) -> usize {
    let bits = u64::BITS.saturating_sub(v.leading_zeros());
    (bits.saturating_add(6) / 7).max(1) as usize
}

/// ZigZag: `0 → 0, −1 → 1, 1 → 2, …`.
pub const fn zigzag(v: i64) -> u64 {
    (v.wrapping_shl(1) ^ (v >> 63)).cast_unsigned()
}

/// The inverse of [`zigzag`].
pub const fn unzigzag(u: u64) -> i64 {
    (u >> 1).cast_signed() ^ (u & 1).cast_signed().wrapping_neg()
}

/// Decodes one canonical LEB128 `u64` from the front of `bytes`; returns it and its length.
pub fn decode_u64(bytes: &[u8]) -> Result<(u64, usize), RepErr> {
    let mut r = Reader::new(bytes);
    let v = r.leb_u64()?;
    Ok((v, r.pos()))
}

/// A cursor over input bytes. Every read is checked; nothing here panics.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub const fn pos(&self) -> usize {
        self.pos
    }

    pub const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The unread bytes.
    pub fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// The bytes from `start` to the cursor.
    pub fn since(&self, start: usize) -> &'a [u8] {
        self.buf.get(start..self.pos).unwrap_or(&[])
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], RepErr> {
        let end = self.pos.checked_add(n).ok_or(RepErr::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(RepErr::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    pub fn array<const K: usize>(&mut self) -> Result<[u8; K], RepErr> {
        self.bytes(K)?.try_into().map_err(|_| RepErr::Truncated)
    }

    pub fn u8(&mut self) -> Result<u8, RepErr> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    pub fn u16(&mut self) -> Result<u16, RepErr> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, RepErr> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, RepErr> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// One canonical LEB128 `u64`.
    pub fn leb_u64(&mut self) -> Result<u64, RepErr> {
        let mut v = 0u64;
        let mut shift = 0u32;
        for i in 0..LEB_MAX_BYTES {
            let b = self.u8()?;
            if i == LEB_MAX_BYTES.saturating_sub(1) && b > 1 {
                return Err(RepErr::Leb);
            }
            v |= u64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
            if b & 0x80 == 0 {
                if b == 0 && i != 0 {
                    return Err(RepErr::Leb);
                }
                return Ok(v);
            }
            shift = shift.saturating_add(7);
        }
        Err(RepErr::Leb)
    }

    pub fn leb_u32(&mut self) -> Result<u32, RepErr> {
        u32::try_from(self.leb_u64()?).map_err(|_| RepErr::Range)
    }

    pub fn leb_u16(&mut self) -> Result<u16, RepErr> {
        u16::try_from(self.leb_u64()?).map_err(|_| RepErr::Range)
    }

    /// One canonical LEB128 of a ZigZag value.
    pub fn leb_i64(&mut self) -> Result<i64, RepErr> {
        Ok(unzigzag(self.leb_u64()?))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn len_matches_encoding() {
        for v in [0, 1, 127, 128, 16_383, 16_384, u64::MAX >> 1, u64::MAX] {
            let mut out = Vec::new();
            put_u64(&mut out, v);
            assert_eq!(out.len(), len_u64(v), "{v}");
            assert_eq!(decode_u64(&out).unwrap(), (v, out.len()));
        }
    }

    #[test]
    fn zigzag_order() {
        let pairs = [(0, 0), (-1, 1), (1, 2), (-2, 3), (2, 4)];
        for (s, u) in pairs {
            assert_eq!(zigzag(s), u);
            assert_eq!(unzigzag(u), s);
        }
        assert_eq!(zigzag(i64::MAX), u64::MAX - 1);
        assert_eq!(zigzag(i64::MIN), u64::MAX);
    }
}
