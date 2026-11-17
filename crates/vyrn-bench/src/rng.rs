//! The generator's PRNGs (02 §6.2): xoshiro256** per session, seeded through SplitMix64.
//!
//! Both are implemented here from the published algorithms (Vigna and Blackman, prng.di.unimi.it)
//! and checked against their reference outputs in the tests, so no crate's release can change the
//! stream (B4). Everything is integer arithmetic.

/// SplitMix64. Seeds [`Xoshiro256`] and mixes seeds.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// xoshiro256**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    /// The state is the first four outputs of SplitMix64(`seed`), as the authors recommend.
    pub fn from_seed(seed: u64) -> Self {
        let mut sm = SplitMix64::new(seed);
        Self {
            s: [sm.next_u64(), sm.next_u64(), sm.next_u64(), sm.next_u64()],
        }
    }

    /// A stream from an explicit state. It must not be all zero.
    pub const fn from_state(s: [u64; 4]) -> Self {
        Self { s }
    }

    /// The stream of one session (02 §6.2): SplitMix64(`run_seed` ⊕ (`SessionId` << 1)).
    pub fn for_session(run_seed: u64, session: u32) -> Self {
        Self::from_seed(run_seed ^ (u64::from(session) << 1))
    }

    /// The stream of the global burst process. Bit 63 is never set in `SessionId` << 1, so this
    /// seed cannot equal a session's.
    pub fn for_global(run_seed: u64) -> Self {
        Self::from_seed(run_seed ^ (1 << 63))
    }

    pub fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = self.s;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s1 << 17;
        let s2 = s2 ^ s0;
        let s3 = s3 ^ s1;
        let s1 = s1 ^ s2;
        let s0 = s0 ^ s3;
        let s2 = s2 ^ t;
        let s3 = s3.rotate_left(45);
        self.s = [s0, s1, s2, s3];
        result
    }

    /// Uniform on [0, n) without modulo bias (Lemire's multiply-and-reject). `n` = 0 gives 0.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let mut m = u128::from(self.next_u64()) * u128::from(n);
        let mut low = low64(m);
        if low < n {
            let threshold = n.wrapping_neg() % n;
            while low < threshold {
                m = u128::from(self.next_u64()) * u128::from(n);
                low = low64(m);
            }
        }
        high64(m)
    }

    /// Uniform on [lo, hi].
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        let span = hi.wrapping_sub(lo).wrapping_add(1);
        if span == 0 {
            return self.next_u64();
        }
        lo.wrapping_add(self.below(span))
    }

    /// True with probability `ppm` / 10⁶.
    pub fn chance_ppm(&mut self, ppm: u32) -> bool {
        self.below(1_000_000) < u64::from(ppm)
    }
}

fn low64(x: u128) -> u64 {
    u64::try_from(x & u128::from(u64::MAX)).unwrap_or(0)
}

fn high64(x: u128) -> u64 {
    u64::try_from(x >> 64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference `splitmix64.c` outputs for seed 0 (the sequence every port of the algorithm
    /// quotes).
    #[test]
    fn splitmix64_seed_zero_matches_reference() {
        let mut sm = SplitMix64::new(0);
        let got: Vec<u64> = (0..5).map(|_| sm.next_u64()).collect();
        assert_eq!(
            got,
            [
                0xE220_A839_7B1D_CDAF,
                0x6E78_9E6A_A1B9_65F4,
                0x06C4_5D18_8009_454F,
                0xF88B_B8A8_724C_81EC,
                0x1B39_896A_51A8_749B,
            ]
        );
    }

    /// `SplitMix64::seed_from_u64(1234567)` in the `rand_xoshiro` test suite.
    #[test]
    fn splitmix64_seed_1234567_matches_reference() {
        let mut sm = SplitMix64::new(1_234_567);
        let got: Vec<u64> = (0..5).map(|_| sm.next_u64()).collect();
        assert_eq!(
            got,
            [
                6_457_827_717_110_365_317,
                3_203_168_211_198_807_973,
                9_817_491_932_198_370_423,
                4_593_380_528_125_082_431,
                16_408_922_859_458_223_821,
            ]
        );
    }

    /// State {1, 2, 3, 4}: the vector of the `rand_xoshiro` test suite, which is the output of
    /// the reference `xoshiro256starstar.c`.
    #[test]
    fn xoshiro256ss_state_1234_matches_reference() {
        let mut x = Xoshiro256::from_state([1, 2, 3, 4]);
        let got: Vec<u64> = (0..10).map(|_| x.next_u64()).collect();
        assert_eq!(
            got,
            [
                11_520,
                0,
                1_509_978_240,
                1_215_971_899_390_074_240,
                1_216_172_134_540_287_360,
                607_988_272_756_665_600,
                16_172_922_978_634_559_625,
                8_476_171_486_693_032_832,
                10_595_114_339_597_558_777,
                2_904_607_092_377_533_576,
            ]
        );
    }

    /// Seeding goes through the first four SplitMix64(0) outputs above. Expected values come from
    /// running the reference C algorithm on that state.
    #[test]
    fn xoshiro256ss_seeded_from_splitmix_matches_reference() {
        let mut x = Xoshiro256::from_seed(0);
        assert_eq!(
            x,
            Xoshiro256::from_state([
                0xE220_A839_7B1D_CDAF,
                0x6E78_9E6A_A1B9_65F4,
                0x06C4_5D18_8009_454F,
                0xF88B_B8A8_724C_81EC,
            ])
        );
        let got: Vec<u64> = (0..5).map(|_| x.next_u64()).collect();
        assert_eq!(
            got,
            [
                0x99EC_5F36_CB75_F2B4,
                0xBF6E_1F78_4956_452A,
                0x1A5F_849D_4933_E6E0,
                0x6AA5_94F1_262D_2D2C,
                0xBBA5_AD4A_1F84_2E59,
            ]
        );
    }

    #[test]
    fn session_streams_use_run_seed_xor_session_shifted() {
        let a = Xoshiro256::for_session(0x1234, 0x0010_0003);
        assert_eq!(a, Xoshiro256::from_seed(0x1234 ^ (0x0010_0003 << 1)));
        assert_ne!(a, Xoshiro256::for_session(0x1234, 0x0010_0004));
        assert_ne!(
            Xoshiro256::for_global(0x1234),
            Xoshiro256::for_session(0x1234, 0)
        );
    }

    #[test]
    fn below_is_in_range_and_unbiased_on_a_tiny_modulus() {
        let mut x = Xoshiro256::from_seed(7);
        assert_eq!(x.below(0), 0);
        assert_eq!(x.below(1), 0);
        let mut seen = [0u32; 3];
        for _ in 0..30_000 {
            let v = usize::try_from(x.below(3)).unwrap_or(99);
            seen[v] += 1;
        }
        // Each bucket expects 10,000 with σ ≈ 82: ±600 is more than 7σ.
        assert!(
            seen.iter().all(|&c| (9_400..=10_600).contains(&c)),
            "{seen:?}"
        );
        for _ in 0..1000 {
            assert!((5..=9).contains(&x.range(5, 9)));
        }
    }
}
