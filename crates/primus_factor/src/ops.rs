/// Lazy modular multiplication by a precomputed factor.
///
/// Implementations return a value in the representation-specific lazy range,
/// usually `[0, 2 * modulus)`, and callers can canonicalize it with a final
/// modular reduction when needed.
///
/// The factor must have been precomputed for the `modulus` supplied to each
/// call.
pub trait LazyFactorMul<T> {
    /// Calculates `self * b (mod 2 * modulus)` for canonical `b`.
    fn lazy_factor_mul_modulo(self, b: T, modulus: T) -> T;
}

/// Canonical modular multiplication by a precomputed factor.
///
/// The factor must have been precomputed for the `modulus` supplied to each
/// call, and the result is in `[0, modulus)`.
pub trait FactorMul<T>: LazyFactorMul<T> {
    /// Calculates `self * b (mod modulus)` for canonical `b`.
    fn factor_mul_modulo(self, b: T, modulus: T) -> T;
}

/// Slice-level lazy multiplication by a precomputed factor.
///
/// Implementations may use SIMD internally when the `simd` feature is enabled.
/// Callers keep the normal scalar slice layout, and the remainder is handled by
/// the scalar path.
///
/// The factor must have been precomputed for the `modulus` supplied to each
/// call. Input slice elements are expected to be canonical.
pub trait LazyFactorSliceOps<T> {
    /// Calculates `factor * value (mod 2 * modulus)` for each element in-place.
    fn lazy_factor_mul_slice_assign(self, values: &mut [T], modulus: T);

    /// Calculates `factor * input (mod 2 * modulus)` into `output`.
    ///
    /// # Debug assertions
    ///
    /// Debug builds assert that `input.len() == output.len()`. Release builds
    /// assume callers provide equal-length slices.
    fn lazy_factor_mul_slice_to(self, input: &[T], output: &mut [T], modulus: T);
}

/// Slice-level canonical multiplication by a precomputed factor.
///
/// Implementations may use SIMD internally when the `simd` feature is enabled.
/// Callers keep the normal scalar slice layout, and the remainder is handled by
/// the scalar path.
///
/// The factor must have been precomputed for the `modulus` supplied to each
/// call. Input and accumulator slice elements are expected to be canonical.
pub trait FactorSliceOps<T>: LazyFactorSliceOps<T> {
    /// Calculates `factor * value (mod modulus)` for each element in-place.
    fn factor_mul_slice_assign(self, values: &mut [T], modulus: T);

    /// Calculates `factor * input (mod modulus)` into `output`.
    ///
    /// # Debug assertions
    ///
    /// Debug builds assert that `input.len() == output.len()`. Release builds
    /// assume callers provide equal-length slices.
    fn factor_mul_slice_to(self, input: &[T], output: &mut [T], modulus: T);

    /// Calculates `acc += factor * rhs (mod modulus)` element-wise.
    ///
    /// # Debug assertions
    ///
    /// Debug builds assert that `acc.len() == rhs.len()`. Release builds
    /// assume callers provide equal-length slices.
    fn add_factor_mul_slice_assign(self, acc: &mut [T], rhs: &[T], modulus: T);

    /// Calculates `acc -= factor * rhs (mod modulus)` element-wise.
    ///
    /// Useful for NTT inverse butterflies where `factor` is a fixed twiddle.
    ///
    /// # Debug assertions
    ///
    /// Debug builds assert that `acc.len() == rhs.len()`. Release builds
    /// assume callers provide equal-length slices.
    fn sub_factor_mul_slice_assign(self, acc: &mut [T], rhs: &[T], modulus: T);

    /// Calculates `output[i] = factor * rhs[i] + addend[i] (mod modulus)`.
    ///
    /// Useful for NTT forward butterflies where `factor` is a fixed twiddle.
    ///
    /// # Debug assertions
    ///
    /// Debug builds assert that `rhs`, `addend`, and `output` have equal lengths.
    /// Release builds assume callers provide equal-length slices.
    fn factor_mul_add_slice_to(self, rhs: &[T], addend: &[T], output: &mut [T], modulus: T);
}
