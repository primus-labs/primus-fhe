use std::simd::cmp::SimdOrd;

use primus_integer::{CarryingAdd, SimdArray, SimdUnsignedInteger, WideningMul};

pub use crate::common::uint::simd::{lazy_reduce_neg, reduce_neg, reduce_once};

mod mul;

pub use mul::*;

#[inline]
pub fn reduce_add<T>(m: T::SimdT, a: T::SimdT, b: T::SimdT) -> T::SimdT
where
    T: SimdUnsignedInteger,
{
    let sum = a + b;
    sum.simd_min(sum - m)
}

#[inline]
pub fn reduce_double<T>(m: T::SimdT, a: T::SimdT) -> T::SimdT
where
    T: SimdUnsignedInteger,
{
    let sum = a << T::SimdT::splat(T::ONE);
    sum.simd_min(sum - m)
}

#[inline]
pub fn reduce_sub<T>(m: T::SimdT, a: T::SimdT, b: T::SimdT) -> T::SimdT
where
    T: SimdUnsignedInteger,
{
    // `a, b ∈ [0, m)`. When `a >= b`, `diff = a - b < m` and `diff + m < 2m`
    // does not wrap (provided `m < 2^{BITS-1}`), so `min` picks `diff`.
    // When `a < b`, `diff` wraps to a huge value and `diff + m` wraps back to
    // the canonical `(a - b) mod m`, so `min` picks the wrapped-back result.
    // Lowers to a single `vpminuq` on AVX-512.
    let diff = a - b;
    diff.simd_min(diff + m)
}

#[inline]
pub fn lazy_reduce_sub<T>(m: T::SimdT, a: T::SimdT, b: T::SimdT) -> T::SimdT
where
    T: SimdUnsignedInteger,
{
    m - b + a
}

#[inline]
pub fn multiply_add<T: SimdUnsignedInteger>(c: &mut [T::SimdT; 2], a: T::SimdT, b: T::SimdT) {
    let (lw, hw) = a.widening_mul(b);
    let carry;
    (c[0], carry) = c[0].overflowing_add(lw);
    (c[1], _) = c[1].carrying_add(hw, carry);
}

// ===========================================================================
// SIMD slice kernels.
// ===========================================================================

pub use crate::common::uint::simd::{
    lazy_reduce_neg_slice_assign, lazy_reduce_neg_slice_to, reduce_neg_slice_assign,
    reduce_neg_slice_to, reduce_once_slice_assign, reduce_once_slice_to,
};

#[inline]
pub fn reduce_add_slice_assign<T: SimdUnsignedInteger>(modulus: T, a: &mut [T], b: &[T]) {
    debug_assert_eq!(a.len(), b.len());
    let m = T::SimdT::splat(modulus);
    let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    for (ac, bc) in a_chunks.iter_mut().zip(b_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *ac = reduce_add::<T>(m, av, bv).to_array();
    }
    for (a, &b) in a_rem.iter_mut().zip(b_rem) {
        super::reduce_add_assign(modulus, a, b);
    }
}

#[inline]
pub fn reduce_add_slice_to<T: SimdUnsignedInteger>(modulus: T, a: &[T], b: &[T], output: &mut [T]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), output.len());
    let m = T::SimdT::splat(modulus);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);
    for ((ac, bc), oc) in a_chunks.iter().zip(b_chunks).zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *oc = reduce_add::<T>(m, av, bv).to_array();
    }
    for ((&a, &b), o) in a_rem.iter().zip(b_rem).zip(o_rem) {
        *o = super::reduce_add(modulus, a, b);
    }
}

#[inline]
pub fn reduce_sub_slice_assign<T: SimdUnsignedInteger>(modulus: T, a: &mut [T], b: &[T]) {
    debug_assert_eq!(a.len(), b.len());
    let m = T::SimdT::splat(modulus);
    let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    for (ac, bc) in a_chunks.iter_mut().zip(b_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *ac = reduce_sub::<T>(m, av, bv).to_array();
    }
    for (a, &b) in a_rem.iter_mut().zip(b_rem) {
        super::reduce_sub_assign(modulus, a, b);
    }
}

#[inline]
pub fn reduce_sub_slice_to<T: SimdUnsignedInteger>(modulus: T, a: &[T], b: &[T], output: &mut [T]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), output.len());
    let m = T::SimdT::splat(modulus);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);
    for ((ac, bc), oc) in a_chunks.iter().zip(b_chunks).zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *oc = reduce_sub::<T>(m, av, bv).to_array();
    }
    for ((&a, &b), o) in a_rem.iter().zip(b_rem).zip(o_rem) {
        *o = super::reduce_sub(modulus, a, b);
    }
}

#[inline]
pub fn reduce_sub_slice_rev_assign<T: SimdUnsignedInteger>(modulus: T, a: &[T], b: &mut [T]) {
    debug_assert_eq!(a.len(), b.len());
    let m = T::SimdT::splat(modulus);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks_mut(b);
    for (ac, bc) in a_chunks.iter().zip(b_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *bc = reduce_sub::<T>(m, av, bv).to_array();
    }
    for (&a, b) in a_rem.iter().zip(b_rem) {
        *b = super::reduce_sub(modulus, a, *b);
    }
}

#[inline]
pub fn reduce_double_slice_assign<T: SimdUnsignedInteger>(modulus: T, values: &mut [T]) {
    let m = T::SimdT::splat(modulus);
    let (chunks, rem) = T::simd_as_chunks_mut(values);
    for chunk in chunks {
        let v = T::SimdT::from_array(*chunk);
        *chunk = reduce_double::<T>(m, v).to_array();
    }
    for value in rem {
        super::reduce_double_assign(modulus, value);
    }
}
#[inline]
pub fn reduce_double_slice_to<T: SimdUnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    let m = T::SimdT::splat(modulus);
    let (in_chunks, in_rem) = T::simd_as_chunks(input);
    let (out_chunks, out_rem) = T::simd_as_chunks_mut(output);
    for (i, o) in in_chunks.iter().zip(out_chunks) {
        let v = T::SimdT::from_array(*i);
        *o = reduce_double::<T>(m, v).to_array();
    }
    for (&i, o) in in_rem.iter().zip(out_rem) {
        *o = super::reduce_double(modulus, i);
    }
}

#[inline]
pub fn lazy_reduce_sub_slice_assign<T: SimdUnsignedInteger>(modulus: T, a: &mut [T], b: &[T]) {
    debug_assert_eq!(a.len(), b.len());
    let m = T::SimdT::splat(modulus);
    let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    for (ac, bc) in a_chunks.iter_mut().zip(b_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *ac = lazy_reduce_sub::<T>(m, av, bv).to_array();
    }
    for (a, &b) in a_rem.iter_mut().zip(b_rem) {
        super::lazy_reduce_sub_assign(modulus, a, b);
    }
}

#[inline]
pub fn lazy_reduce_sub_slice_to<T: SimdUnsignedInteger>(
    modulus: T,
    a: &[T],
    b: &[T],
    output: &mut [T],
) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), output.len());
    let m = T::SimdT::splat(modulus);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);
    for ((ac, bc), oc) in a_chunks.iter().zip(b_chunks).zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *oc = lazy_reduce_sub::<T>(m, av, bv).to_array();
    }
    for ((&a, &b), o) in a_rem.iter().zip(b_rem).zip(o_rem) {
        *o = super::lazy_reduce_sub(modulus, a, b);
    }
}

#[inline]
pub fn lazy_reduce_sub_slice_rev_assign<T: SimdUnsignedInteger>(modulus: T, a: &[T], b: &mut [T]) {
    debug_assert_eq!(a.len(), b.len());
    let m = T::SimdT::splat(modulus);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks_mut(b);
    for (ac, bc) in a_chunks.iter().zip(b_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *bc = lazy_reduce_sub::<T>(m, av, bv).to_array();
    }
    for (&a, b) in a_rem.iter().zip(b_rem) {
        *b = super::lazy_reduce_sub(modulus, a, *b);
    }
}
