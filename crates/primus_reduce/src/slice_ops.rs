//! Slice-level (bulk) modular operations.
//!
//! These traits mirror the scalar `Reduce*` traits in [`crate::ops`] but
//! operate on whole slices, so that implementations can dispatch to a
//! SIMD kernel internally and amortize the per-call overhead.
//!
//! Each trait bundles an in-place (`*_assign`) form and an out-of-place
//! (`*_to`) form. There are no default impls: every modulus type provides
//! its own body, which is typically a thin wrapper around a hand-written
//! scalar / SIMD kernel.
//!
//! # Length and value-range invariants
//!
//! Most slice traits use `debug_assert*!` to check length agreement and
//! value-range pre-conditions. In release builds those checks are stripped;
//! callers (typically the polynomial / NTT layer) are expected to uphold
//! them at higher-level boundaries. APIs that document panics, such as
//! [`ReduceDotProduct::reduce_dot_product`], perform unconditional checks.

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
pub trait ReduceAddSlice<T, B = T> {
    /// Calculates `a[i] = (a[i] + b[i]) (mod modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    fn reduce_add_slice_assign(self, a: &mut [T], b: &[B]);

    /// Writes `a[i] + b[i] (mod modulus)` into `output[i]` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == output.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    fn reduce_add_slice_to(self, a: &[T], b: &[B], output: &mut [T]);
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
pub trait ReduceSubSlice<T, B = T> {
    /// Calculates `a[i] = (a[i] - b[i]) (mod modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    fn reduce_sub_slice_assign(self, a: &mut [T], b: &[B]);

    /// Writes `a[i] - b[i] (mod modulus)` into `output[i]` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == output.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    fn reduce_sub_slice_to(self, a: &[T], b: &[B], output: &mut [T]);

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
///
/// # Scratch buffer
///
/// `reduce_inv_slice_assign` requires a scratch buffer of length >=
/// `values.len()`. The scratch buffer is used for prefix-product
/// computation in batch-inversion algorithms (e.g. Montgomery batch
/// inversion). It is not needed by `reduce_inv_slice_to`, which can
/// reuse `output` as working space.
pub trait ReduceInvSlice<T> {
    /// Calculates `values[i] = values[i]^(-1) (mod modulus)` in-place,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `scratch.len() >= values.len()`
    /// - Each `values[i] < modulus`
    /// - Each `values[i]` and `modulus` must be coprime
    ///
    /// # Panics
    ///
    /// Panics if any element has no inverse modulo `modulus`. Use
    /// [`TryReduceInvSlice`] for a non-panicking variant.
    fn reduce_inv_slice_assign(self, values: &mut [T], scratch: &mut [T]);

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
    /// [`TryReduceInvSlice`] for a non-panicking variant.
    fn reduce_inv_slice_to(self, input: &[T], output: &mut [T]);
}

/// Fallible slice form of [`crate::TryReduceInv`].
pub trait TryReduceInvSlice<T> {
    /// Try to calculate `values[i] = values[i]^(-1) (mod modulus)` in-place,
    /// where `self` is the modulus.
    ///
    /// # Errors
    ///
    /// Returns [`ReduceError::NoInverseAtIndex`](crate::ReduceError::NoInverseAtIndex)
    /// for the first element that has no inverse.
    fn try_reduce_inv_slice_assign(
        self,
        values: &mut [T],
        scratch: &mut [T],
    ) -> Result<(), crate::ReduceError<T>>;

    /// Try to calculate `output[i] = input[i]^(-1) (mod modulus)`,
    /// where `self` is the modulus.
    ///
    /// # Errors
    ///
    /// Returns [`ReduceError::NoInverseAtIndex`](crate::ReduceError::NoInverseAtIndex)
    /// for the first element that has no inverse.
    fn try_reduce_inv_slice_to(
        self,
        input: &[T],
        output: &mut [T],
    ) -> Result<(), crate::ReduceError<T>>;
}

/// The modular dot product.
///
/// This is always used for slice. For example, `u64` slice `[u64]`.
///
/// For two same length slice `a = (a₀, a₁, ..., an)` and `b = (b₀, b₁, ..., bn)`.
///
/// This trait will calculate `a₀×b₀ + a₁×b₁ + ... + an×bn mod modulus`.
pub trait ReduceDotProduct<T> {
    /// Output type.
    type Output;

    /// Calculate `∑a_i×b_i (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - Each `a_i < modulus` and `b_i < modulus`
    ///
    /// # Panics
    ///
    /// Panics if `a.as_ref().len() != b.as_ref().len()`.
    #[must_use]
    fn reduce_dot_product(self, a: impl AsRef<[T]>, b: impl AsRef<[T]>) -> Self::Output;

    /// Calculate `∑a_i×b_i (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - Each `a_i < modulus` and `b_i < modulus`
    /// - If the iterators yield different numbers of elements, iteration
    ///   stops at the shorter (standard `zip` semantics); callers that
    ///   require equal length should use [`reduce_dot_product`](Self::reduce_dot_product).
    #[must_use]
    fn reduce_dot_product_iter(
        self,
        a: impl IntoIterator<Item = T>,
        b: impl IntoIterator<Item = T>,
    ) -> Self::Output;
}
