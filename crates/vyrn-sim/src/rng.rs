//! Per-component random streams (11 §6.4): ChaCha8 seeded with `BLAKE3(seed_le ‖ name)`.

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// The stream of component `name` under `seed`.
pub fn stream(seed: u64, name: &str) -> ChaCha8Rng {
    let mut h = blake3::Hasher::new();
    h.update(&seed.to_le_bytes());
    h.update(name.as_bytes());
    ChaCha8Rng::from_seed(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::stream;
    use rand::Rng;

    #[test]
    fn streams_are_independent_and_repeatable() {
        let a = stream(7, "net").next_u64();
        assert_eq!(a, stream(7, "net").next_u64());
        assert_ne!(a, stream(7, "faults").next_u64());
        assert_ne!(a, stream(8, "net").next_u64());
    }
}
