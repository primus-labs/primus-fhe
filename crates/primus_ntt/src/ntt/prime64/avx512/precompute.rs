use aligned_vec::AVec;
use primus_factor::MultiplyFactor;

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
