//! SplitMix64 PRNG (pinned, §1 of SPEC-conformance.md). All wrapping u64.
//! Conformance: next() from seed=0 returns 0xE220A8397B1DCDAF first.

pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        // "the seed IS the state (no warm-up)"
        SplitMix64 { state: seed }
    }

    pub fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// bounded(n) := next() mod n ; n==0 → 0. PINNED as a plain modulo.
    pub fn bounded(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}
