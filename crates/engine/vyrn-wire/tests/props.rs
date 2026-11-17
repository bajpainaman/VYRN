//! Arbitrary bytes never panic a parser, and whatever decodes re-encodes to the same bytes, so
//! there is exactly one encoding of every message and record (04 VR1).

use proptest::prelude::*;
use vyrn_wire::{Msg, Record, Request, Response};

proptest! {
    #[test]
    fn msg_decode_is_canonical(b in any::<[u8; 16]>(), kind in prop::sample::select(vec![1u8, 2, 3, 4, 0x10, 0x11, 0x12])) {
        let mut b = b;
        b[0] = kind;
        if let Ok(m) = Msg::decode(&b) {
            prop_assert_eq!(m.encode(), b);
        }
    }

    #[test]
    fn record_decode_is_canonical(b in any::<[u8; 16]>(), kind in 0x81u8..=0x88, w in 0u16..30) {
        let mut b = b;
        b[0] = kind;
        b[2..4].copy_from_slice(&w.to_le_bytes());
        if let Ok(r) = Record::decode(&b) {
            prop_assert_eq!(r.encode(), b);
        }
    }

    #[test]
    fn packet_parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300), count in 0u8..20) {
        let mut bytes = bytes;
        if let Some(c) = bytes.get_mut(8) {
            *c = count;
        }
        if let Ok(p) = Request::parse(&bytes) {
            prop_assert_eq!(bytes.len(), 32 + 16 * usize::from(count));
            let _ = p.check_header();
            prop_assert_eq!(p.msgs().count(), usize::from(count));
        }
        if let Ok(p) = Response::parse(&bytes) {
            prop_assert_eq!(bytes.len(), 24 + 16 * usize::from(count));
            prop_assert_eq!(p.records().count(), usize::from(count));
        }
    }
}
