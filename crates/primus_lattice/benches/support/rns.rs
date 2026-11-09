// Q then P from primus_glwe_rns/benches/key_switching.rs. The four-modulus
// case treats their union as one ordinary RNS base, not a hybrid Q/P split.
pub const MODULI: [u64; 4] = [
    1_125_899_906_826_241,
    1_125_899_906_629_633,
    1_125_899_906_031_617,
    1_125_899_904_679_937,
];

// (log N, dimension, modulus count, log B): vary one axis from the first case.
pub const CASES: &[(u32, usize, usize, u32)] = &[
    (10, 1, 2, 20),
    (11, 1, 2, 20),
    (10, 2, 2, 20),
    (10, 1, 4, 20),
    (10, 1, 2, 10),
];

// Canonical [component][modulus][coefficient] data. Independent residues avoid
// restricting decomposition to small integers occupying only the lowest limb.
pub fn coefficients(len: usize, n: usize, moduli: &[u64], seed: u64) -> Vec<u64> {
    let mut state = seed;
    (0..len)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % moduli[i / n % moduli.len()]
        })
        .collect()
}
