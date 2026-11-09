//! Maps odd-root evaluations through a backend's Fourier storage order.

use primus_shape::PolyLength;

/// Both bundled backends evaluate at exp(i*pi*(1-4*j)/N), j=0..N/2.
/// An odd exponent maps these roots either to stored roots or their conjugates.
/// The table supplies a checked length with N >= 32 and a bijection from
/// standard frequency indices to storage indices in `0..N/2`.
pub(crate) fn automorphism_map(
    poly_length: PolyLength,
    degree: usize,
    storage_index: impl Fn(usize) -> usize,
) -> Vec<(usize, bool)> {
    let n = poly_length.get();
    let two_n = 2 * n;
    assert!(
        degree < two_n && degree & 1 == 1,
        "FFT automorphism degree must be odd and less than 2N"
    );
    let mask = two_n - 1;
    let mut map = vec![(0, false); n / 2];
    for j in 0..n / 2 {
        // Wrapping arithmetic is exact modulo the power-of-two 2N.
        let root = 1usize.wrapping_sub(4usize.wrapping_mul(j));
        let mut mapped = degree.wrapping_mul(root) & mask;
        let conjugate = mapped & 3 == 3;
        if conjugate {
            mapped = mapped.wrapping_neg() & mask;
        }
        let source = (1usize.wrapping_sub(mapped) & mask) / 4;
        map[storage_index(j)] = (storage_index(source), conjugate);
    }
    map
}
