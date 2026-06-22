//! Value-side mirror of `primus_reduce::lazy_slice_ops`.
//!
//! Results are in `[0, 2 * modulus)`; callers must perform a final
//! reduction (e.g. via [`crate::slice_ops::OnceModuloSlice`]) when a
//! canonical representative is required.

use primus_reduce::prelude::*;

/// Value-side mirror of [`LazyReduceMulSlice`].
pub trait LazyMulModuloSlice<M, T> {
    /// `self[i] = self[i] * b[i] (mod 2 * modulus)` element-wise.
    fn lazy_mul_modulo_slice_assign(&mut self, b: &[T], modulus: M);

    /// `output[i] = self[i] * b[i] (mod 2 * modulus)`.
    fn lazy_mul_modulo_slice_to(&self, b: &[T], output: &mut [T], modulus: M);

    /// `self[i] = self[i] * scalar (mod 2 * modulus)` element-wise.
    fn lazy_mul_scalar_modulo_slice_assign(&mut self, scalar: T, modulus: M);

    /// `output[i] = self[i] * scalar (mod 2 * modulus)`.
    fn lazy_mul_scalar_modulo_slice_to(&self, scalar: T, output: &mut [T], modulus: M);
}

impl<T, M> LazyMulModuloSlice<M, T> for [T]
where
    M: LazyReduceMulSlice<T> + Copy,
{
    #[inline(always)]
    fn lazy_mul_modulo_slice_assign(&mut self, b: &[T], modulus: M) {
        modulus.lazy_reduce_mul_slice_assign(self, b);
    }

    #[inline(always)]
    fn lazy_mul_modulo_slice_to(&self, b: &[T], output: &mut [T], modulus: M) {
        modulus.lazy_reduce_mul_slice_to(self, b, output);
    }

    #[inline(always)]
    fn lazy_mul_scalar_modulo_slice_assign(&mut self, scalar: T, modulus: M) {
        modulus.lazy_reduce_mul_scalar_slice_assign(self, scalar);
    }

    #[inline(always)]
    fn lazy_mul_scalar_modulo_slice_to(&self, scalar: T, output: &mut [T], modulus: M) {
        modulus.lazy_reduce_mul_scalar_slice_to(self, scalar, output);
    }
}

/// Value-side mirror of [`LazyReduceMulAddSlice`].
pub trait LazyMulAddModuloSlice<M, T> {
    /// `self[i] += a[i] * b[i] (mod 2 * modulus)`.
    fn lazy_add_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M);

    /// `self[i] -= a[i] * b[i] (mod 2 * modulus)`.
    fn lazy_sub_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M);

    /// `self[i] += a[i] * scalar (mod 2 * modulus)` — scalar FMAC accumulate.
    fn lazy_add_mul_scalar_modulo_slice_assign(&mut self, a: &[T], scalar: T, modulus: M);

    /// `output[i] = self[i] * b[i] + c[i] (mod 2 * modulus)`.
    fn lazy_mul_add_modulo_slice_to(&self, b: &[T], c: &[T], output: &mut [T], modulus: M);

    /// `output[i] = self[i] * scalar + c[i] (mod 2 * modulus)`.
    fn lazy_mul_scalar_add_modulo_slice_to(&self, scalar: T, c: &[T], output: &mut [T], modulus: M);
}

impl<T, M> LazyMulAddModuloSlice<M, T> for [T]
where
    M: LazyReduceMulAddSlice<T> + Copy,
{
    #[inline(always)]
    fn lazy_add_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M) {
        modulus.lazy_reduce_add_mul_slice_assign(self, a, b);
    }

    #[inline(always)]
    fn lazy_sub_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M) {
        modulus.lazy_reduce_sub_mul_slice_assign(self, a, b);
    }

    #[inline(always)]
    fn lazy_add_mul_scalar_modulo_slice_assign(&mut self, a: &[T], scalar: T, modulus: M) {
        modulus.lazy_reduce_add_mul_scalar_slice_assign(self, a, scalar);
    }

    #[inline(always)]
    fn lazy_mul_add_modulo_slice_to(&self, b: &[T], c: &[T], output: &mut [T], modulus: M) {
        modulus.lazy_reduce_mul_add_slice_to(self, b, c, output);
    }

    #[inline(always)]
    fn lazy_mul_scalar_add_modulo_slice_to(
        &self,
        scalar: T,
        c: &[T],
        output: &mut [T],
        modulus: M,
    ) {
        modulus.lazy_reduce_mul_scalar_add_slice_to(self, scalar, c, output);
    }
}

/// Value-side mirror of [`LazyReduceSubSlice`].
pub trait LazySubModuloSlice<M, B: ?Sized = Self> {
    /// `self[i] = self[i] - b[i] (mod 2 * modulus)` element-wise.
    fn lazy_sub_modulo_slice_assign(&mut self, b: &B, modulus: M);

    /// `output[i] = self[i] - b[i] (mod 2 * modulus)`.
    fn lazy_sub_modulo_slice_to(&self, b: &B, output: &mut Self, modulus: M);

    /// `b[i] = self[i] - b[i] (mod 2 * modulus)` — reverse direction.
    fn lazy_sub_modulo_slice_rev_assign(&self, b: &mut Self, modulus: M);
}

impl<T, M, B> LazySubModuloSlice<M, [B]> for [T]
where
    M: LazyReduceSubSlice<T, B> + Copy,
{
    #[inline(always)]
    fn lazy_sub_modulo_slice_assign(&mut self, b: &[B], modulus: M) {
        modulus.lazy_reduce_sub_slice_assign(self, b);
    }

    #[inline(always)]
    fn lazy_sub_modulo_slice_to(&self, b: &[B], output: &mut [T], modulus: M) {
        modulus.lazy_reduce_sub_slice_to(self, b, output);
    }

    #[inline(always)]
    fn lazy_sub_modulo_slice_rev_assign(&self, b: &mut [T], modulus: M) {
        modulus.lazy_reduce_sub_slice_rev_assign(self, b);
    }
}

/// Value-side mirror of [`LazyReduceNegSlice`].
pub trait LazyNegModuloSlice<M> {
    /// `v = -v (mod 2 * modulus)` for each element in-place.
    fn lazy_neg_modulo_slice_assign(&mut self, modulus: M);

    /// `output[i] = -self[i] (mod 2 * modulus)`.
    fn lazy_neg_modulo_slice_to(&self, output: &mut Self, modulus: M);
}

impl<T, M> LazyNegModuloSlice<M> for [T]
where
    M: LazyReduceNegSlice<T> + Copy,
{
    #[inline(always)]
    fn lazy_neg_modulo_slice_assign(&mut self, modulus: M) {
        modulus.lazy_reduce_neg_slice_assign(self);
    }

    #[inline(always)]
    fn lazy_neg_modulo_slice_to(&self, output: &mut [T], modulus: M) {
        modulus.lazy_reduce_neg_slice_to(self, output);
    }
}
