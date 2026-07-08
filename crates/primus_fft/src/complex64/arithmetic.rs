use num_complex::Complex64;

/// Pointwise fused multiply-add: `accumulator[i] += lhs[i] * rhs[i]` for all `i`.
///
/// This is the hot-path accumulation used in external product and CMUX
/// operations. All slices must have the same length.
#[inline]
pub fn add_mul_assign(accumulator: &mut [Complex64], lhs: &[Complex64], rhs: &[Complex64]) {
    debug_assert_eq!(accumulator.len(), lhs.len());
    debug_assert_eq!(accumulator.len(), rhs.len());
    for (acc, (&l, &r)) in accumulator.iter_mut().zip(lhs.iter().zip(rhs.iter())) {
        *acc += l * r;
    }
}

/// Pointwise multiply: `output[i] = lhs[i] * rhs[i]` for all `i`.
///
/// All slices must have the same length.
#[inline]
pub fn mul_to(lhs: &[Complex64], rhs: &[Complex64], output: &mut [Complex64]) {
    debug_assert_eq!(lhs.len(), output.len());
    debug_assert_eq!(rhs.len(), output.len());
    for ((&l, &r), out) in lhs.iter().zip(rhs.iter()).zip(output.iter_mut()) {
        *out = l * r;
    }
}
