//! Integer replacements for `ln`, `exp` and friends. The generator uses no floating point
//! (B4: the same bytes on x86-64, aarch64 and macOS), so every distribution is built from these
//! and from [`crate::rng::Xoshiro256`]. All results are truncated, never rounded by the FPU.

/// ln 2 in Q32.
const LN2_Q32: u64 = 2_977_044_472;
/// 2^(2^-k) in Q62 for k = 1 ..= 32 (computed offline with 60 digits; checked by a test that
/// squaring each entry gives the one before it).
const EXP2_FRAC: [u64; 32] = [
    0x5A82_7999_FCEF_3242,
    0x4C1B_F828_C6DC_54B8,
    0x45CA_E0F1_F545_EB73,
    0x42D5_61B3_E624_3D8A,
    0x4166_C34C_5615_D0EC,
    0x40B2_68F9_DE01_83BA,
    0x4058_F6A7_ECCC_D5B6,
    0x402C_6BE9_6AF2_FB58,
    0x4016_321B_6870_27A8,
    0x400B_1817_8BA3_3B14,
    0x4005_8BCE_4101_47E8,
    0x4002_C5D7_BFF7_1DAF,
    0x4001_62E8_07EE_7E5B,
    0x4000_B173_0DF6_A524,
    0x4000_58B9_497B_8152,
    0x4000_2C5C_955D_D701,
    0x4000_162E_46D6_F26C,
    0x4000_0B17_2275_7B1B,
    0x4000_058B_90FD_3E0C,
    0x4000_02C5_C86F_3F26,
    0x4000_0162_E433_C79B,
    0x4000_00B1_7218_EDD0,
    0x4000_0058_B90C_3968,
    0x4000_002C_5C86_0D54,
    0x4000_0016_2E43_02D2,
    0x4000_000B_1721_8073,
    0x4000_0005_8B90_BFFC,
    0x4000_0002_C5C8_5FEF,
    0x4000_0001_62E4_2FF3,
    0x4000_0000_B172_17F9,
    0x4000_0000_58B9_0BFC,
    0x4000_0000_2C5C_85FE,
];

/// log2(`x`) in Q32 for `x` > 0 (0 gives 0). Bitwise: the integer part is the bit position, the
/// fraction comes from repeated squaring of the mantissa.
pub fn log2_q32(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    let lz = x.leading_zeros();
    let int = u64::from(63 - lz);
    // Mantissa in [1, 2) as Q63.
    let mut m = x << lz;
    let mut frac = 0u64;
    for _ in 0..32 {
        let sq = (u128::from(m) * u128::from(m)) >> 63;
        frac <<= 1;
        if sq >= 1u128 << 64 {
            frac |= 1;
            m = u64::try_from(sq >> 1).unwrap_or(u64::MAX);
        } else {
            m = u64::try_from(sq).unwrap_or(u64::MAX);
        }
    }
    int << 32 | frac
}

/// 2^`x` in Q32 for `x` in Q32, as a `u128` (so 2^60 still fits); saturates for `x` ≥ 60 · 2^32.
pub fn exp2_q32(x: u64) -> u128 {
    let int = x >> 32;
    if int >= 60 {
        return u128::MAX;
    }
    let mut acc: u128 = 1 << 62; // 1.0 in Q62
    for (k, c) in EXP2_FRAC.iter().enumerate() {
        if x >> (31 - k) & 1 == 1 {
            acc = (acc * u128::from(*c)) >> 62;
        }
    }
    // Q62 → Q32, then the integer power of two.
    acc >> 30 << int
}

/// ⌊`lo` · (`hi` / `lo`)^U⌋ for U = `u` / 2^64: log-uniform on [`lo`, `hi` − 1] (02 §6.5, §6.7).
/// `lo` ≥ 1; `hi` ≤ `lo` gives `lo`.
pub fn log_uniform(lo: u64, hi: u64, u: u64) -> u64 {
    let lo = lo.max(1);
    if hi <= lo {
        return lo;
    }
    let span = log2_q32(hi) - log2_q32(lo);
    let e = u64::try_from((u128::from(span) * u128::from(u)) >> 64).unwrap_or(0);
    let m = exp2_q32(e & 0xFFFF_FFFF); // 2^frac, Q32
    let v = ((u128::from(lo) * m) << (e >> 32)) >> 32;
    u64::try_from(v).unwrap_or(hi - 1).clamp(lo, hi - 1)
}

/// −ln(u) in Q32 for u = `x` / 2^64, `x` > 0: an Exp(1) variate from one uniform draw.
pub fn neg_ln_q32(x: u64) -> u64 {
    let x = x.max(1);
    let neg_log2 = (64u64 << 32) - log2_q32(x);
    u64::try_from((u128::from(neg_log2) * u128::from(LN2_Q32)) >> 32).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exp2_table_is_a_chain_of_square_roots() {
        // c[k]² = c[k-1] (Q62), within the rounding of the last bits.
        let mut prev = 2u128 << 62;
        for c in EXP2_FRAC {
            let sq = (u128::from(c) * u128::from(c)) >> 62;
            assert!(sq.abs_diff(prev) <= 4, "{c:#x}");
            prev = u128::from(c);
        }
    }

    #[test]
    fn log2_and_exp2_hit_exact_powers_and_known_values() {
        assert_eq!(log2_q32(1), 0);
        assert_eq!(log2_q32(1 << 40), 40 << 32);
        assert_eq!(exp2_q32(0), 1 << 32);
        assert_eq!(exp2_q32(3 << 32), 8 << 32);
        // log2(3) = 1.5849625007…, 2^0.5 = 1.4142135623…, both times 2^32.
        let l3 = log2_q32(3);
        assert!(l3.abs_diff(6_807_362_106) <= 2, "{l3}");
        let r2 = exp2_q32(1 << 31);
        assert!(r2.abs_diff(6_074_001_000) <= 2, "{r2}");
    }

    #[test]
    fn log_uniform_covers_its_range_with_the_right_median() {
        assert_eq!(log_uniform(10, 4096, 0), 10);
        assert_eq!(log_uniform(10, 4096, u64::MAX), 4095);
        // The median of log-uniform is the geometric mean: sqrt(10 · 4096) = 202.4.
        assert!((201..=203).contains(&log_uniform(10, 4096, 1 << 63)));
        // Lifetime row 4 reaches 8 h = 2.88e13 ns without overflow.
        let top = log_uniform(100_000_000, 28_800_000_000_000, u64::MAX);
        assert!(
            top > 28_000_000_000_000 && top < 28_800_000_000_000,
            "{top}"
        );
        assert_eq!(log_uniform(5, 5, 7), 5);
    }

    #[test]
    fn exp2_inverts_log2_to_within_a_few_parts_per_billion() {
        for x in [5u64, 77, 1_000_003, 1 << 33, 0xDEAD_BEEF_CAFE] {
            let back = u64::try_from(exp2_q32(log2_q32(x)) >> 32).unwrap_or(0);
            assert!(back.abs_diff(x) <= x / 1_000_000_000 + 1, "{x} -> {back}");
        }
    }

    #[test]
    fn neg_ln_matches_known_points_and_is_monotone() {
        // u = 1/2: ln 2 = 0.693147… ; u = 2^-10: 10 ln 2.
        assert!(neg_ln_q32(1 << 63).abs_diff(2_977_044_472) <= 2);
        assert!(neg_ln_q32(1 << 54).abs_diff(10 * 2_977_044_472) <= 12);
        assert!(neg_ln_q32(u64::MAX) <= 1);
        let mut prev = u64::MAX;
        for x in [1u64, 1 << 20, 1 << 40, 1 << 60, u64::MAX] {
            let v = neg_ln_q32(x);
            assert!(v < prev);
            prev = v;
        }
    }
}
