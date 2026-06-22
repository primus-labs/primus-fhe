//! Lazy slice-level modular operations.
//!
//! These traits mirror [`crate::lazy_ops`] but operate on whole slices.
//! Results are only guaranteed to be in `[0, 2 * modulus)`; callers must
//! perform a final reduction (e.g. via [`crate::ReduceOnceSlice`]) when a
//! canonical representative is required.
//!
//! See [`crate::slice_ops`] for the conventions on length checks
//! (`debug_assert*!`) and the lack of default impls.

/// Lazy slice form of [`crate::ReduceMul`] / [`crate::LazyReduceMul`].
pub trait LazyReduceMulSlice<T> {
    /// Calculates `a[i] = (a[i] * b[i]) (mod 2 * modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] * b[i] < modulus²`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_slice_assign(self, a: &mut [T], b: &[T]);

    /// Writes `a[i] * b[i] (mod 2 * modulus)` into `output[i]`
    /// element-wise, where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == output.len()`
    /// - Each `a[i] * b[i] < modulus²`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]);

    /// Calculates `a[i] = (a[i] * scalar) (mod 2 * modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `scalar < modulus`
    /// - Each `a[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T);

    /// Writes `a[i] * scalar (mod 2 * modulus)` into `output[i]`
    /// element-wise, where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == output.len()`
    /// - `scalar < modulus`, each `a[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]);
}

/// Lazy slice form of [`crate::ReduceSub`] / [`crate::LazyReduceSub`].
pub trait LazyReduceSubSlice<T, B = T> {
    /// Calculates `a[i] = (a[i] - b[i]) (mod 2 * modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_sub_slice_assign(self, a: &mut [T], b: &[B]);

    /// Writes `a[i] - b[i] (mod 2 * modulus)` into `output[i]` element-wise,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == output.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_sub_slice_to(self, a: &[T], b: &[B], output: &mut [T]);

    /// Calculates `b[i] = (a[i] - b[i]) (mod 2 * modulus)` element-wise,
    /// where `self` is the modulus.
    ///
    /// This is the reverse direction: the second slice is mutated instead of
    /// the first.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_sub_slice_rev_assign(self, a: &[T], b: &mut [T]);
}

/// Lazy slice form of [`crate::ReduceNeg`] / [`crate::LazyReduceNeg`].
pub trait LazyReduceNegSlice<T> {
    /// Calculates `v = -v (mod 2 * modulus)` for each element in-place,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - Each `values[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_neg_slice_assign(self, values: &mut [T]);

    /// Writes `-input[i] (mod 2 * modulus)` into `output[i]` for each element,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `input.len() == output.len()`
    /// - Each `input[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_neg_slice_to(self, input: &[T], output: &mut [T]);
}

/// Lazy slice form of [`crate::ReduceMulAdd`] / [`crate::LazyReduceMulAdd`].
///
/// Same five shapes as [`crate::ReduceMulAddSlice`]; results are in
/// `[0, 2 * modulus)`.
pub trait LazyReduceMulAddSlice<T> {
    /// Calculates `acc[i] = (acc[i] + a[i] * b[i]) (mod 2 * modulus)`
    /// element-wise, where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `acc.len() == a.len() == b.len()`
    /// - Each `acc[i] < modulus`, `a[i] < modulus`, `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]);

    /// Calculates `acc[i] = (acc[i] - a[i] * b[i]) (mod 2 * modulus)`
    /// element-wise, where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `acc.len() == a.len() == b.len()`
    /// - Each `acc[i] < modulus`, `a[i] < modulus`, `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]);

    /// Calculates `acc[i] = (acc[i] + a[i] * scalar) (mod 2 * modulus)`
    /// element-wise, where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `acc.len() == a.len()`
    /// - `scalar < modulus`, each `acc[i] < modulus`, `a[i] < modulus`
    fn lazy_reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], a: &[T], scalar: T);

    /// Writes `a[i] * b[i] + c[i] (mod 2 * modulus)` into `output[i]`,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == c.len() == output.len()`
    /// - Each `a[i] < modulus`, `b[i] < modulus`, `c[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]);

    /// Writes `a[i] * scalar + c[i] (mod 2 * modulus)` into `output[i]`,
    /// where `self` is the modulus.
    ///
    /// # Correctness
    ///
    /// - `a.len() == c.len() == output.len()`
    /// - `scalar < modulus`, each `a[i] < modulus`, `c[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_scalar_add_slice_to(self, a: &[T], scalar: T, c: &[T], output: &mut [T]);
}
