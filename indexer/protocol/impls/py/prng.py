"""SplitMix64 PRNG (SPEC-conformance.md §1) — self-implemented, stdlib only.

All arithmetic wraps mod 2^64 (Python int is unbounded; mask every step).
"""

MASK64 = (1 << 64) - 1
GAMMA = 0x9E3779B97F4A7C15
M1 = 0xBF58476D1CE4E5B9
M2 = 0x94D049BB133111EB


class SplitMix64:
    def __init__(self, seed):
        # "the seed IS the state (no warm-up)"
        self.state = seed & MASK64

    def next(self):
        self.state = (self.state + GAMMA) & MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * M1) & MASK64
        z = ((z ^ (z >> 27)) * M2) & MASK64
        return z ^ (z >> 31)

    def bounded(self, n):
        # "n>0; n==0 -> 0. PINNED as a plain modulo."
        if n == 0:
            return 0
        return self.next() % n


def _selftest():
    r = SplitMix64(0)
    first = r.next()
    assert first == 0xE220A8397B1DCDAF, hex(first)


if __name__ == "__main__":
    _selftest()
    print("prng selftest ok")
