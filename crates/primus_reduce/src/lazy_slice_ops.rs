//! Lazy slice-level modular operations.
//!
//! These traits mirror [`crate::lazy_ops`] but operate on whole slices.
//! Results remain congruent to the corresponding expression modulo `modulus`
//! but are only guaranteed to be in `[0, 2 * modulus)`. Callers must perform a
//! final reduction, for example via [`crate::ReduceOnceSlice`], when a
//! canonical representative is required.
//!
//! See [`crate::slice_ops`] for the conventions on length checks
//! (`debug_assert*!`) and the lack of default impls.

/// Lazy slice form of [`crate::ReduceMul`] / [`crate::LazyReduceMul`].
pub trait LazyReduceMulSlice<T> {
    /// Replaces each `a[i]` with a lazy representative of `a[i] * b[i]`
    /// modulo `self`.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] * b[i] < modulus²`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_slice_assign(self, a: &mut [T], b: &[T]);

    /// Writes a lazy representative of `a[i] * b[i]` modulo `self` into each
    /// `output[i]`.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == output.len()`
    /// - Each `a[i] * b[i] < modulus²`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]);

    /// Replaces each `a[i]` with a lazy representative of `a[i] * scalar`
    /// modulo `self`.
    ///
    /// # Correctness
    ///
    /// - `scalar < modulus`
    /// - Each `a[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T);

    /// Writes a lazy representative of `a[i] * scalar` modulo `self` into each
    /// `output[i]`.
    ///
    /// # Correctness
    ///
    /// - `a.len() == output.len()`
    /// - `scalar < modulus`, each `a[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]);
}

/// Lazy slice form of [`crate::ReduceSub`] / [`crate::LazyReduceSub`].
pub trait LazyReduceSubSlice<T> {
    /// Replaces each `a[i]` with a lazy representative of `a[i] - b[i]`
    /// modulo `self`.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_sub_slice_assign(self, a: &mut [T], b: &[T]);

    /// Writes a lazy representative of `a[i] - b[i]` modulo `self` into each
    /// `output[i]`.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == output.len()`
    /// - Each `a[i] < modulus` and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_sub_slice_to(self, a: &[T], b: &[T], output: &mut [T]);

    /// Replaces each `b[i]` with a lazy representative of `a[i] - b[i]`
    /// modulo `self`.
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
    /// Replaces each value with a lazy representative of its negation modulo
    /// `self`.
    ///
    /// # Correctness
    ///
    /// - Each `values[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_neg_slice_assign(self, values: &mut [T]);

    /// Writes a lazy representative of `-input[i]` modulo `self` into each
    /// `output[i]`.
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
    /// Replaces each `acc[i]` with a lazy representative of
    /// `acc[i] + a[i] * b[i]` modulo `self`.
    ///
    /// # Correctness
    ///
    /// - `acc.len() == a.len() == b.len()`
    /// - Each `acc[i] < modulus`, `a[i] < modulus`, `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]);

    /// Replaces each `acc[i]` with a lazy representative of
    /// `acc[i] - a[i] * b[i]` modulo `self`.
    ///
    /// # Correctness
    ///
    /// - `acc.len() == a.len() == b.len()`
    /// - Each `acc[i] < modulus`, `a[i] < modulus`, `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]);

    /// Replaces each `acc[i]` with a lazy representative of
    /// `acc[i] + a[i] * scalar` modulo `self`.
    ///
    /// # Correctness
    ///
    /// - `acc.len() == a.len()`
    /// - `scalar < modulus`, each `acc[i] < modulus`, `a[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], a: &[T], scalar: T);

    /// Writes a lazy representative of `a[i] * b[i] + c[i]` modulo `self`
    /// into each `output[i]`.
    ///
    /// # Correctness
    ///
    /// - `a.len() == b.len() == c.len() == output.len()`
    /// - Each `a[i] < modulus`, `b[i] < modulus`, `c[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]);

    /// Writes a lazy representative of `a[i] * scalar + c[i]` modulo `self`
    /// into each `output[i]`.
    ///
    /// # Correctness
    ///
    /// - `a.len() == c.len() == output.len()`
    /// - `scalar < modulus`, each `a[i] < modulus`, `c[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_reduce_mul_scalar_add_slice_to(self, a: &[T], scalar: T, c: &[T], output: &mut [T]);
}
