//! Slice-level (bulk) modular operations.
//!
//! These traits mirror the scalar operation traits but work on whole slices,
//! allowing implementations to dispatch to a SIMD kernel and amortize
//! per-call overhead.
//!
//! Element-wise traits generally provide in-place (`*_assign`) and
//! out-of-place (`*_to`) forms. There are no default implementations: each
//! modulus type selects its scalar or SIMD kernel.
//!
//! # Length and value-range invariants
//!
//! Implementations may use `debug_assert*!` to diagnose shape mismatches.
//! Release callers, typically the polynomial or NTT layer, must validate
//! lengths at a higher-level boundary and must always uphold the documented
//! value ranges. APIs that document panics, such as
//! [`ReduceDotProduct::reduce_dot_product`], check their stated conditions in
//! every build profile.

/// Slice form of [`crate::ReduceOnce`].
pub trait ReduceOnceSlice<T> {
    /// For each `v` in `values`: `v -= modulus` if `v >= modulus`, where
    /// `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - Each `values[i] < 2 * modulus`
    /// - Each result is `< modulus`
    fn reduce_once_slice_assign(self, values: &mut [T]);

    /// For each `v` in `input`: writes `v - modulus` if `v >= modulus`,
    /// otherwise `v`, into `output`, where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `input.len() == output.len()`
    /// - Each `input[i] < 2 * modulus`
    /// - Each result is `< modulus`
    fn reduce_once_slice_to(self, input: &[T], output: &mut [T]);
}

/// Slice form of [`crate::ReduceNeg`].
pub trait ReduceNegSlice<T> {
    /// Calculates `v = -v (mod modulus)` for each element in-place, where
    /// `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - Each `values[i] < modulus`
    fn reduce_neg_slice_assign(self, values: &mut [T]);

    /// Writes `-input[i] (mod modulus)` into `output[i]` for each element,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `input.len() == output.len()`
    /// - Each `input[i] < modulus`
    fn reduce_neg_slice_to(self, input: &[T], output: &mut [T]);
}

/// Slice form of [`crate::ReduceAdd`].
pub trait ReduceAddSlice<T> {
    /// Calculates `a[i] = (a[i] + b[i]) (mod modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    fn reduce_add_slice_assign(self, a: &mut [T], b: &[T]);

    /// Writes `a[i] + b[i] (mod modulus)` into `output[i]` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == output.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    fn reduce_add_slice_to(self, a: &[T], b: &[T], output: &mut [T]);
}

/// Slice form of [`crate::ReduceDouble`].
pub trait ReduceDoubleSlice<T> {
    /// Calculates `v[i] = (2 * v[i]) (mod modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - Each `values[i] < modulus`
    fn reduce_double_slice_assign(self, values: &mut [T]);

    /// Writes `2 * input[i] (mod modulus)` into `output[i]` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `input.len() == output.len()`
    /// - Each `input[i] < modulus`
    fn reduce_double_slice_to(self, input: &[T], output: &mut [T]);
}

/// Slice form of [`crate::ReduceSub`].
pub trait ReduceSubSlice<T> {
    /// Calculates `a[i] = (a[i] - b[i]) (mod modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    fn reduce_sub_slice_assign(self, a: &mut [T], b: &[T]);

    /// Writes `a[i] - b[i] (mod modulus)` into `output[i]` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == output.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    fn reduce_sub_slice_to(self, a: &[T], b: &[T], output: &mut [T]);

    /// Calculates `b[i] = (a[i] - b[i]) (mod modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// This is the reverse direction of [`reduce_sub_slice_assign`](ReduceSubSlice::reduce_sub_slice_assign):
    /// the second slice is mutated instead of the first.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    fn reduce_sub_slice_rev_assign(self, a: &[T], b: &mut [T]);
}

/// Slice form of [`crate::ReduceMul`].
pub trait ReduceMulSlice<T> {
    /// Calculates `a[i] = (a[i] * b[i]) (mod modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] * b[i] < modulus²`
    fn reduce_mul_slice_assign(self, a: &mut [T], b: &[T]);

    /// Writes `a[i] * b[i] (mod modulus)` into `output[i]` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == output.len()`
    /// - Each `a[i] * b[i] < modulus²`
    fn reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]);

    /// Calculates `a[i] = (a[i] * scalar) (mod modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `scalar < modulus`
    /// - Each `a[i] < modulus`
    fn reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T);

    /// Writes `a[i] * scalar (mod modulus)` into `output[i]` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == output.len()`
    /// - `scalar < modulus`, each `a[i] < modulus`
    fn reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]);
}

/// Slice form of [`crate::ReduceMulAdd`].
///
/// Provides the five fused multiply-add shapes that the polynomial /
/// NTT layer needs:
///
/// 1. `acc[i] += a[i] * b[i]`              — FMAC accumulate
/// 2. `acc[i] -= a[i] * b[i]`              — fused multiply-subtract
/// 3. `out[i]  = a[i] * b[i] + c[i]`       — three-input one-output
/// 4. `out[i]  = scalar * b[i] + c[i]`     — scalar × slice plus addend
/// 5. `acc[i] += scalar * b[i]`            — scalar FMAC accumulate
pub trait ReduceMulAddSlice<T> {
    /// Calculates `acc[i] = (acc[i] + a[i] * b[i]) (mod modulus)`
    /// element-wise, where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `acc.len() == a.len() == b.len()`
    /// - Each `acc[i] < modulus`, `a[i] < modulus`, `b[i] < modulus`
    fn reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]);

    /// Calculates `acc[i] = (acc[i] - a[i] * b[i]) (mod modulus)`
    /// element-wise, where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `acc.len() == a.len() == b.len()`
    /// - Each `acc[i] < modulus`, `a[i] < modulus`, `b[i] < modulus`
    fn reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]);

    /// Calculates `acc[i] = (acc[i] + a[i] * scalar) (mod modulus)`
    /// element-wise, where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `acc.len() == a.len()`
    /// - `scalar < modulus`, each `acc[i] < modulus`, `a[i] < modulus`
    fn reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], a: &[T], scalar: T);

    /// Writes `a[i] * b[i] + c[i] (mod modulus)` into `output[i]`,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == c.len() == output.len()`
    /// - Each `a[i] < modulus`, `b[i] < modulus`, `c[i] < modulus`
    fn reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]);

    /// Writes `a[i] * scalar + c[i] (mod modulus)` into `output[i]`,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == c.len() == output.len()`
    /// - `scalar < modulus`, each `a[i] < modulus`, `c[i] < modulus`
    fn reduce_mul_scalar_add_slice_to(self, a: &[T], scalar: T, c: &[T], output: &mut [T]);
}

/// Slice form of [`crate::ReduceInv`].
pub trait ReduceInvSlice<T> {
    /// Writes `input[i]^(-1) (mod modulus)` into `output[i]` for each element,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `input.len() == output.len()`
    /// - Each `input[i] < modulus`
    /// - Each `input[i]` and `modulus` must be coprime
    ///
    /// # Panics
    ///
    /// Panics if any element has no inverse modulo `modulus`. Use
    /// [`TryReduceInvSlice`] for a non-panicking inverse.
    fn reduce_inv_slice_to(self, input: &[T], output: &mut [T]);
}

/// Fallible slice form of [`crate::TryReduceInv`].
pub trait TryReduceInvSlice<T> {
    /// Attempts to write each input's multiplicative inverse to `output`,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `input.len() == output.len()`
    /// - Each `input[i] < modulus`
    ///
    /// # Errors
    ///
    /// Returns an inverse-related [`ReduceError`](crate::ReduceError) if one or
    /// more input values have no inverse. `output` may be modified when an
    /// error is returned.
    fn try_reduce_inv_slice_to(
        self,
        input: &[T],
        output: &mut [T],
    ) -> Result<(), crate::ReduceError<T>>;
}

/// Modular dot products of slices or iterators.
///
/// Canonical operands are supported by every implementation. An implementation
/// may document a wider input range; callers using it must establish that
/// implementation's bounds, rather than assume them from this trait alone.
pub trait ReduceDotProduct<T> {
    /// Calculates `∑ a[i] * b[i] (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// Each operand is below `modulus`, or satisfies a wider range explicitly
    /// documented by the implementation.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() != b.len()`.
    #[must_use]
    fn reduce_dot_product(self, a: &[T], b: &[T]) -> T;

    /// Calculates `∑ a_i * b_i (mod modulus)` using standard `zip` semantics.
    ///
    /// # Correctness
    ///
    /// Each operand is below `modulus`, or satisfies a wider range explicitly
    /// documented by the implementation.
    ///
    /// # Behavior
    ///
    /// If the iterators have different lengths, iteration stops at the shorter
    /// one. Use [`reduce_dot_product`](Self::reduce_dot_product) when equal
    /// lengths must be enforced.
    #[must_use]
    fn reduce_dot_product_iter(
        self,
        a: impl IntoIterator<Item = T>,
        b: impl IntoIterator<Item = T>,
    ) -> T;
}
