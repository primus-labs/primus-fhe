use aligned_vec::AVec;

/// Builds the HEXL-compatible forward-root layout.
///
/// T4 and T2 roots are duplicated so each stage can load a complete vector
/// without permuting twiddles in the transform kernel. The resulting regions
/// are:
///
/// - `[0, n/8)`: roots for T8 stages
/// - `[n/8, 5n/8)`: roots for T4 stages (each duplicated 4×)
/// - `[5n/8, 9n/8)`: roots for T2 stages (each duplicated 2×)
/// - `[9n/8, 13n/8)`: roots for T1 stages
pub fn build_avx512_root_powers(n: usize, root_of_unity_powers: &[u64]) -> AVec<u64> {
    debug_assert_eq!(root_of_unity_powers.len(), n);

    let mut avx512_roots = AVec::with_capacity(64, 13 * n / 8);
    avx512_roots.extend_from_slice(&root_of_unity_powers[..n / 8]);
    for &root in &root_of_unity_powers[n / 8..n / 4] {
        avx512_roots.extend_from_slice(&[root; 4]);
    }
    for &root in &root_of_unity_powers[n / 4..n / 2] {
        avx512_roots.extend_from_slice(&[root; 2]);
    }
    avx512_roots.extend_from_slice(&root_of_unity_powers[n / 2..]);
    avx512_roots
}
