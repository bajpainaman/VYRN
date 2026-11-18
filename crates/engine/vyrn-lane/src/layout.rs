//! The byte layouts of `OrderSlot` (05 §4.3), `Segment16` (§4.6) and `JEnt` (§4.9) as arena
//! words: word `k` holds bytes `8k .. 8k + 8`, little-endian. Decoders are total.

use vyrn_bbo::{JEnt, JKind, OrderFlags, OrderSlot, Segment16, SlotKind};
use vyrn_types::{LaneId, LaneSeq, Nanos, Tick};

/// Sizes of one lane's arena, fixed before `seal()` (`INV-NOALLOC`).
#[derive(Clone, Copy, Debug)]
pub struct ArenaConfig {
    /// `ENG_SLOT_CAP`: slot 0 is null (05 §4.2).
    pub slot_cap: u32,
    /// `ENG_SEG_CAP`: segment 0 is null.
    pub seg_cap: u32,
    /// The book's ladder (05 §13.1). The directory is dense over it (PR follow-up: the 05 §4.6
    /// window and overflow pages).
    pub tick_min: Tick,
    pub tick_max: Tick,
    /// Lane-local accounts (`AcctKill` entries).
    pub accounts: u32,
    /// `ENG_JOURNAL`, a power of two.
    pub journal: u32,
}

/// Words `8k..8k+8` of a line as `(lo u32, hi u32)`.
#[inline(always)]
pub(crate) fn halves(w: u64) -> (u32, u32) {
    let [a, b, c, d, e, f, g, h] = w.to_le_bytes();
    (
        u32::from_le_bytes([a, b, c, d]),
        u32::from_le_bytes([e, f, g, h]),
    )
}

#[inline(always)]
pub(crate) fn join(lo: u32, hi: u32) -> u64 {
    u64::from(lo) | (u64::from(hi) << 32)
}

fn kind_code(k: SlotKind) -> u8 {
    match k {
        SlotKind::Original => 0,
        SlotKind::KeepPrio => 1,
        SlotKind::NewPrio => 2,
    }
}

fn kind_of(c: u8) -> SlotKind {
    match c {
        1 => SlotKind::KeepPrio,
        2 => SlotKind::NewPrio,
        _ => SlotKind::Original,
    }
}

/// `OrderSlot` → 8 words.
pub(crate) fn slot_to_words(s: &OrderSlot) -> [u64; 8] {
    let w7 = u64::from_le_bytes({
        let r = s.root.to_le_bytes();
        [
            r[0],
            r[1],
            r[2],
            r[3],
            s.flags.0,
            s.gen_,
            kind_code(s.kind),
            s.tomb_lane.0,
        ]
    });
    [
        s.prio_ts.0,
        s.ins_seq.0,
        s.ins_ts,
        s.tomb_seq.0,
        s.tomb_ts.0,
        join(s.next_ver, s.tick.0),
        join(s.total, s.acct_ix),
        w7,
    ]
}

/// 8 words → `OrderSlot`.
pub(crate) fn slot_from_words(w: &[u64; 8]) -> OrderSlot {
    let [w0, w1, w2, w3, w4, w5, w6, w7] = *w;
    let (next_ver, tick) = halves(w5);
    let (total, acct_ix) = halves(w6);
    let [r0, r1, r2, r3, flags, gen_, kind, tomb_lane] = w7.to_le_bytes();
    OrderSlot {
        prio_ts: Nanos(w0),
        ins_seq: LaneSeq(w1),
        ins_ts: w2,
        tomb_seq: LaneSeq(w3),
        tomb_ts: Nanos(w4),
        next_ver,
        tick: Tick(tick),
        total,
        acct_ix,
        root: u32::from_le_bytes([r0, r1, r2, r3]),
        flags: OrderFlags(flags),
        gen_,
        kind: kind_of(kind),
        tomb_lane: LaneId(tomb_lane),
    }
}

/// Word and shift of `u32` entry `i` of a 16-entry array starting at word `base`.
pub(crate) fn u32_at(base: usize, i: usize) -> (usize, u32) {
    (base.saturating_add(i >> 1), if i & 1 == 0 { 0 } else { 32 })
}

/// Word and shift of `dts[i]` (words 20–23, four per word).
pub(crate) fn dts_at(i: usize) -> (usize, u32) {
    let sh = u32::try_from((i & 3).saturating_mul(16)).unwrap_or(0);
    (20usize.saturating_add(i >> 2), sh)
}

/// 24 words → `Segment16`.
pub(crate) fn seg_from_words(w: &[u64; 24]) -> Segment16 {
    let at = |k: usize| w.get(k).copied().unwrap_or(0);
    let lane32 = |base: usize, i: usize| {
        let (k, sh) = u32_at(base, i);
        u32::try_from((at(k) >> sh) & 0xFFFF_FFFF).unwrap_or(0)
    };
    let (mask, gen_) = halves(at(16));
    let (succ, tick) = halves(at(17));
    let [side, _, v0, v1, ..] = at(18).to_le_bytes();
    Segment16 {
        slot: core::array::from_fn(|i| lane32(0, i)),
        qty: core::array::from_fn(|i| lane32(8, i)),
        mask,
        gen_,
        succ,
        tick: Tick(tick),
        side,
        vmask: u16::from_le_bytes([v0, v1]),
        base_ts: Nanos(at(19)),
        dts: core::array::from_fn(|i| {
            let (k, sh) = dts_at(i);
            u16::try_from((at(k) >> sh) & 0xFFFF).unwrap_or(0)
        }),
    }
}

/// Word 18: `side`, rsv, `vmask`.
pub(crate) fn seg_word18(side: u8, vmask: u16) -> u64 {
    let [v0, v1] = vmask.to_le_bytes();
    u64::from_le_bytes([side, 0, v0, v1, 0, 0, 0, 0])
}

fn jkind_code(k: JKind) -> u8 {
    match k {
        JKind::New => 1,
        JKind::KeepPrio => 2,
        JKind::NewPrio => 3,
        JKind::Tomb => 4,
        JKind::AcctKill => 5,
    }
}

/// `JEnt` (16 B): `seq u64 | tick u32 | slot u24 | kind u8`.
pub(crate) fn jent_to_words(j: &JEnt) -> [u64; 2] {
    let s = j.slot.to_le_bytes();
    let t = j.tick.0.to_le_bytes();
    [
        j.seq.0,
        u64::from_le_bytes([t[0], t[1], t[2], t[3], s[0], s[1], s[2], jkind_code(j.kind)]),
    ]
}

pub(crate) fn jent_from_words(w: &[u64; 2]) -> Option<JEnt> {
    let [seq, w1] = *w;
    let [t0, t1, t2, t3, s0, s1, s2, k] = w1.to_le_bytes();
    let kind = match k {
        1 => JKind::New,
        2 => JKind::KeepPrio,
        3 => JKind::NewPrio,
        4 => JKind::Tomb,
        5 => JKind::AcctKill,
        _ => return None,
    };
    Some(JEnt {
        seq: LaneSeq(seq),
        tick: Tick(u32::from_le_bytes([t0, t1, t2, t3])),
        slot: u32::from_le_bytes([s0, s1, s2, 0]),
        kind,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod arena_layout_tests {
    use super::*;
    use vyrn_bbo::{Side, Stp, Tif};

    /// Byte offsets of 05 §4.3, checked on the little-endian image.
    #[test]
    fn slot_words_are_the_05_4_3_table() {
        let s = OrderSlot {
            prio_ts: Nanos(0x0102_0304_0506_0708),
            ins_seq: LaneSeq(0x1112_1314_1516_1718),
            ins_ts: 0x2122_2324_2526_2728,
            tomb_seq: LaneSeq(0x3132_3334_3536_3738),
            tomb_ts: Nanos(0x4142_4344_4546_4748),
            next_ver: 0x5152_5354,
            tick: Tick(0x5556_5758),
            total: 0x6162_6364,
            acct_ix: 0x6566_6768,
            root: 0x7172_7374,
            flags: OrderFlags::new(Side::Sell, Tif::Ioc, false, Stp::CancelBoth),
            gen_: 0x7A,
            kind: SlotKind::NewPrio,
            tomb_lane: LaneId(0x7C),
        };
        let img: Vec<u8> = slot_to_words(&s)
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let at = |o: usize, n: usize| img.get(o..o + n).unwrap_or(&[]).to_vec();
        assert_eq!(at(0, 8), 0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(at(24, 8), 0x3132_3334_3536_3738u64.to_le_bytes());
        assert_eq!(at(40, 4), 0x5152_5354u32.to_le_bytes(), "next_ver");
        assert_eq!(at(44, 4), 0x5556_5758u32.to_le_bytes(), "tick");
        assert_eq!(at(52, 4), 0x6566_6768u32.to_le_bytes(), "acct_ix");
        assert_eq!(at(56, 4), 0x7172_7374u32.to_le_bytes(), "root");
        assert_eq!(
            at(60, 4),
            vec![0x33, 0x7A, 2, 0x7C],
            "flags (sell 1 | ioc 1<<1 | stp 3<<4) gen kind tomb_lane"
        );
        assert_eq!(slot_from_words(&slot_to_words(&s)), s);
    }

    #[test]
    fn segment_positions_use_the_05_4_6_offsets() {
        let mut w = [0u64; 24];
        let (k, sh) = u32_at(0, 5);
        w[k] |= 0xAAAA_0005u64 << sh;
        let (k, sh) = u32_at(8, 15);
        w[k] |= 0xBBBB_000Fu64 << sh;
        let (k, sh) = dts_at(6);
        w[k] |= 0xCC06u64 << sh;
        w[16] = join(0x0040_0020, 7);
        w[17] = join(9, 1234);
        w[18] = seg_word18(1, 0x0020);
        let img: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
        assert_eq!(img[20..24], 0xAAAA_0005u32.to_le_bytes(), "slot[5] at 4·5");
        assert_eq!(
            img[124..128],
            0xBBBB_000Fu32.to_le_bytes(),
            "qty[15] at 64+4·15"
        );
        assert_eq!(img[172..174], 0xCC06u16.to_le_bytes(), "dts[6] at 160+2·6");
        assert_eq!(img[144], 1, "side");
        assert_eq!(img[146..148], 0x0020u16.to_le_bytes(), "vmask");
        let g = seg_from_words(&w);
        assert_eq!(
            (g.slot[5], g.qty[15], g.dts[6]),
            (0xAAAA_0005, 0xBBBB_000F, 0xCC06)
        );
        assert_eq!(
            (g.mask, g.gen_, g.succ, g.tick.0, g.side, g.vmask),
            (0x0040_0020, 7, 9, 1234, 1, 0x20)
        );
    }

    #[test]
    fn journal_entry_round_trips_with_a_24_bit_slot() {
        let j = JEnt {
            seq: LaneSeq(77),
            tick: Tick(0x0102_0304),
            slot: 0x00AB_CDEF,
            kind: JKind::Tomb,
        };
        let w = jent_to_words(&j);
        assert_eq!(w[1].to_le_bytes(), [4, 3, 2, 1, 0xEF, 0xCD, 0xAB, 4]);
        assert_eq!(jent_from_words(&w), Some(j));
        assert_eq!(jent_from_words(&[1, 0]), None);
    }
}
