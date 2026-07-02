use aligned_vec::{AVec, avec};
use primus_factor::{FactorBase, FactorMul, MultiplyFactor, ShoupFactor};

use crate::reverse::ReverseLsbs;

type Factor = ShoupFactor<u64>;

/// Computes the ordinal powers of the primitive root: [1, w, w^2, ..., w^(2n-1)].
///
/// Returns the vector of size `2n` and the inverse root (w^(2n-1)).
pub fn build_ordinal_powers(root: u64, q: u64, n: usize) -> (Vec<u64>, u64) {
    let root_factor = Factor::new(root, q);

    let mut power = root;

    let mut ordinal_root_powers = vec![0; n * 2];
    let mut iter = ordinal_root_powers.iter_mut();
    *iter.next().unwrap() = 1;
    *iter.next().unwrap() = root;
    for root_power in iter {
        power = root_factor.factor_mul_modulo(power, q);
        *root_power = power;
    }

    let inv_root = *ordinal_root_powers.last().unwrap();

    debug_assert_eq!(root_factor.factor_mul_modulo(inv_root, q), 1);

    (ordinal_root_powers, inv_root)
}

/// Builds bit-reversed forward and inverse root-of-unity power vectors.
///
/// Returns `(root_powers, inv_root_powers, reverse_lsbs)`, each of size `n`.
pub fn build_root_powers(
    n: usize,
    log_n: u32,
    ordinal_root_powers: &[u64],
) -> (AVec<u64>, AVec<u64>, Vec<usize>) {
    let reverse_lsbs: Vec<usize> = (0..n).map(|i| i.reverse_lsbs(log_n)).collect();

    let mut root_of_unity_powers = avec![0; n];
    root_of_unity_powers[0] = 1;
    for (&root_power, &i) in ordinal_root_powers[0..n].iter().zip(reverse_lsbs.iter()) {
        root_of_unity_powers[i] = root_power;
    }

    let mut inv_root_of_unity_powers = avec![0; n];
    inv_root_of_unity_powers[0] = 1;
    for (&inv_root_power, &i) in ordinal_root_powers[n + 1..]
        .iter()
        .rev()
        .zip(reverse_lsbs.iter())
    {
        inv_root_of_unity_powers[i + 1] = inv_root_power;
    }

    (root_of_unity_powers, inv_root_of_unity_powers, reverse_lsbs)
}

/// Builds the AVX512-specialized root-of-unity power arrangement with T4/T2
/// duplication to avoid extra permutations during loading.
///
/// The resulting layout:
/// - `[0, n/8)`: roots for T8 stages
/// - `[n/8, 5n/8)`: roots for T4 stages (each duplicated 4×)
/// - `[5n/8, 9n/8)`: roots for T2 stages (each duplicated 2×)
/// - `[9n/8, 13n/8)`: roots for T1 stages
pub fn build_avx512_root_powers(n: usize, root_of_unity_powers: &[u64]) -> AVec<u64> {
    let mut avx512_roots = AVec::with_capacity(64, n / 8 + 3 * n / 2);

    // Duplicate each root at indices [n/4, n/2] for T2 stages
    let w2_roots: Vec<u64> = root_of_unity_powers[n / 4..n / 2]
        .iter()
        .flat_map(|&x| std::iter::repeat_n(x, 2))
        .collect();

    // Duplicate each root at indices [n/8, n/4] for T4 stages
    let w4_roots: Vec<u64> = root_of_unity_powers[n / 8..n / 4]
        .iter()
        .flat_map(|&x| std::iter::repeat_n(x, 4))
        .collect();

    avx512_roots.extend_from_slice(&root_of_unity_powers[0..n / 8]);
    avx512_roots.extend_from_slice(&w4_roots);
    avx512_roots.extend_from_slice(&w2_roots);
    avx512_roots.extend_from_slice(&root_of_unity_powers[n / 2..]);

    avx512_roots
}

/// Computes a Barrett-preconditioned vector for a given bit-shift.
///
/// For each `value` in `values`, computes `floor(value * 2^bit_shift / q)`.
pub fn build_barrett_vector(values: &[u64], bit_shift: u32, q: u64) -> AVec<u64> {
    AVec::from_iter(
        64,
        values
            .iter()
            .map(|&value| MultiplyFactor::new(value, bit_shift, q).quotient()),
    )
}
