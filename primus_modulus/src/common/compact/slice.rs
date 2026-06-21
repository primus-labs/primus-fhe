use primus_integer::{FheUint, UnsignedInteger};
use primus_reduce::{Modulus, prelude::*};

pub use crate::common::uint::slice::{
    lazy_reduce_neg_slice_assign, lazy_reduce_neg_slice_to, reduce_inv_slice_assign,
    reduce_inv_slice_to, reduce_neg_slice_assign, reduce_neg_slice_to, reduce_once_slice_assign,
    reduce_once_slice_to, try_reduce_inv_slice_assign, try_reduce_inv_slice_to,
};

use super::DOT_PRODUCT_INNER_CHUNK;

/// Adds `b` into `a` element-wise modulo `modulus` using compact-modulus bounds.
#[inline]
pub fn reduce_add_slice_assign<T: UnsignedInteger>(modulus: T, a: &mut [T], b: &[T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter_mut()
        .zip(b)
        .for_each(|(x, &y)| super::reduce_add_assign(modulus, x, y));
}
/// Writes the element-wise sum of `a` and `b` modulo `modulus` into `output`.
#[inline]
pub fn reduce_add_slice_to<T: UnsignedInteger>(modulus: T, a: &[T], b: &[T], output: &mut [T]) {
    debug_assert_eq!(output.len(), a.len());
    debug_assert_eq!(output.len(), b.len());
    output.iter_mut().zip(a).zip(b).for_each(|((out, &x), &y)| {
        *out = super::reduce_add(modulus, x, y);
    });
}

/// Subtracts `b` from `a` element-wise modulo `modulus`.
#[inline]
pub fn reduce_sub_slice_assign<T: UnsignedInteger>(modulus: T, a: &mut [T], b: &[T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter_mut()
        .zip(b)
        .for_each(|(x, &y)| super::reduce_sub_assign(modulus, x, y));
}
/// Writes the element-wise difference `a - b` modulo `modulus` into `output`.
#[inline]
pub fn reduce_sub_slice_to<T: UnsignedInteger>(modulus: T, a: &[T], b: &[T], output: &mut [T]) {
    debug_assert_eq!(output.len(), a.len());
    debug_assert_eq!(output.len(), b.len());
    output.iter_mut().zip(a).zip(b).for_each(|((out, &x), &y)| {
        *out = super::reduce_sub(modulus, x, y);
    });
}
/// Replaces each `b` element with the corresponding `a - b` modulo `modulus`.
#[inline]
pub fn reduce_sub_slice_rev_assign<T: UnsignedInteger>(modulus: T, a: &[T], b: &mut [T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter_mut())
        .for_each(|(&x, y)| *y = super::reduce_sub(modulus, x, *y));
}

/// Doubles each value in place modulo `modulus`.
#[inline]
pub fn reduce_double_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|v| super::reduce_double_assign(modulus, v));
}
/// Writes each doubled `input` value modulo `modulus` into `output`.
#[inline]
pub fn reduce_double_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::reduce_double(modulus, y));
}

/// Applies lazy element-wise subtraction `a += modulus - b`.
#[inline]
pub fn lazy_reduce_sub_slice_assign<T: UnsignedInteger>(modulus: T, a: &mut [T], b: &[T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter_mut()
        .zip(b)
        .for_each(|(x, &y)| super::lazy_reduce_sub_assign(modulus, x, y));
}
/// Writes the lazy element-wise difference `a + modulus - b` into `output`.
#[inline]
pub fn lazy_reduce_sub_slice_to<T: UnsignedInteger>(
    modulus: T,
    a: &[T],
    b: &[T],
    output: &mut [T],
) {
    debug_assert_eq!(output.len(), a.len());
    debug_assert_eq!(output.len(), b.len());
    output.iter_mut().zip(a).zip(b).for_each(|((out, &x), &y)| {
        *out = super::lazy_reduce_sub(modulus, x, y);
    });
}
/// Replaces each `b` element with the lazy difference `a + modulus - b`.
#[inline]
pub fn lazy_reduce_sub_slice_rev_assign<T: UnsignedInteger>(modulus: T, a: &[T], b: &mut [T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter_mut())
        .for_each(|(&x, y)| *y = super::lazy_reduce_sub(modulus, x, *y));
}

/// Multiplies `a` by `b` element-wise in place modulo `modulus`.
#[inline]
pub fn reduce_mul_slice_assign<T, M>(modulus: M, a: &mut [T], b: &[T])
where
    T: FheUint,
    M: Copy + ReduceMulAssign<T>,
{
    debug_assert_eq!(a.len(), b.len());
    a.iter_mut()
        .zip(b)
        .for_each(|(a, &b)| modulus.reduce_mul_assign(a, b));
}

/// Writes the element-wise product of `a` and `b` modulo `modulus` into `output`.
#[inline]
pub fn reduce_mul_slice_to<T, M>(modulus: M, a: &[T], b: &[T], output: &mut [T])
where
    T: FheUint,
    M: Copy + ReduceMul<T, Output = T>,
{
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), output.len());
    a.iter()
        .zip(b)
        .zip(output)
        .for_each(|((&a, &b), o)| *o = modulus.reduce_mul(a, b));
}

/// Multiplies every element of `a` by `scalar` in place modulo `modulus`.
#[inline]
pub fn reduce_mul_scalar_slice_assign<T, M>(modulus: M, a: &mut [T], scalar: T)
where
    T: FheUint,
    M: Copy + ReduceMulAssign<T>,
{
    a.iter_mut()
        .for_each(|a| modulus.reduce_mul_assign(a, scalar));
}

/// Writes each `a` element multiplied by `scalar` modulo `modulus` into `output`.
#[inline]
pub fn reduce_mul_scalar_slice_to<T, M>(modulus: M, a: &[T], scalar: T, output: &mut [T])
where
    T: FheUint,
    M: Copy + ReduceMul<T, Output = T>,
{
    debug_assert_eq!(a.len(), output.len());
    a.iter()
        .zip(output)
        .for_each(|(&a, o)| *o = modulus.reduce_mul(a, scalar));
}

/// Multiplies `a` by `b` element-wise in place using lazy modular reduction.
#[inline]
pub fn lazy_reduce_mul_slice_assign<T, M>(modulus: M, a: &mut [T], b: &[T])
where
    T: FheUint,
    M: Copy + LazyReduceMulAssign<T>,
{
    debug_assert_eq!(a.len(), b.len());
    a.iter_mut()
        .zip(b)
        .for_each(|(a, &b)| modulus.lazy_reduce_mul_assign(a, b));
}

/// Writes lazy element-wise products of `a` and `b` into `output`.
#[inline]
pub fn lazy_reduce_mul_slice_to<T, M>(modulus: M, a: &[T], b: &[T], output: &mut [T])
where
    T: FheUint,
    M: Copy + LazyReduceMul<T, Output = T>,
{
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), output.len());
    a.iter()
        .zip(b)
        .zip(output)
        .for_each(|((&a, &b), o)| *o = modulus.lazy_reduce_mul(a, b));
}

/// Multiplies every element of `a` by `scalar` in place using lazy modular reduction.
#[inline]
pub fn lazy_reduce_mul_scalar_slice_assign<T, M>(modulus: M, a: &mut [T], scalar: T)
where
    T: FheUint,
    M: Copy + LazyReduceMulAssign<T>,
{
    a.iter_mut()
        .for_each(|a| modulus.lazy_reduce_mul_assign(a, scalar));
}

/// Writes lazy products of each `a` element and `scalar` into `output`.
#[inline]
pub fn lazy_reduce_mul_scalar_slice_to<T, M>(modulus: M, a: &[T], scalar: T, output: &mut [T])
where
    T: FheUint,
    M: Copy + LazyReduceMul<T, Output = T>,
{
    debug_assert_eq!(a.len(), output.len());
    a.iter()
        .zip(output)
        .for_each(|(&a, o)| *o = modulus.lazy_reduce_mul(a, scalar));
}

/// Adds the element-wise product `a * b` into `acc` modulo `modulus`.
#[inline]
pub fn reduce_add_mul_slice_assign<T, M>(modulus: M, acc: &mut [T], a: &[T], b: &[T])
where
    T: FheUint,
    M: Copy + ReduceMulAdd<T, Output = T>,
{
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    acc.iter_mut()
        .zip(a)
        .zip(b)
        .for_each(|((acc, &a), &b)| *acc = modulus.reduce_mul_add(a, b, *acc));
}

/// Subtracts the element-wise product `a * b` from `acc` modulo `modulus`.
#[inline]
pub fn reduce_sub_mul_slice_assign<T, M>(modulus: M, acc: &mut [T], a: &[T], b: &[T])
where
    T: FheUint,
    M: Copy + ReduceMul<T, Output = T> + ReduceSubAssign<T>,
{
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    acc.iter_mut().zip(a).zip(b).for_each(|((acc, &a), &b)| {
        let prod = modulus.reduce_mul(a, b);
        modulus.reduce_sub_assign(acc, prod);
    });
}

/// Writes `(a * b + c) mod modulus` element-wise into `output`.
#[inline]
pub fn reduce_mul_add_slice_to<T, M>(modulus: M, a: &[T], b: &[T], c: &[T], output: &mut [T])
where
    T: FheUint,
    M: Copy + ReduceMulAdd<T, Output = T>,
{
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());
    a.iter()
        .zip(b)
        .zip(c)
        .zip(output)
        .for_each(|(((&a, &b), &c), o)| *o = modulus.reduce_mul_add(a, b, c));
}

/// Writes `(a * scalar + c) mod modulus` element-wise into `output`.
#[inline]
pub fn reduce_mul_scalar_add_slice_to<T, M>(
    modulus: M,
    a: &[T],
    scalar: T,
    c: &[T],
    output: &mut [T],
) where
    T: FheUint,
    M: Copy + ReduceMulAdd<T, Output = T>,
{
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());
    a.iter()
        .zip(c)
        .zip(output)
        .for_each(|((&a, &c), o)| *o = modulus.reduce_mul_add(a, scalar, c));
}

/// Adds the element-wise product `a * scalar` into `acc` modulo `modulus`.
#[inline]
pub fn reduce_add_mul_scalar_slice_assign<T, M>(modulus: M, acc: &mut [T], a: &[T], scalar: T)
where
    T: FheUint,
    M: Copy + ReduceMulAdd<T, Output = T>,
{
    debug_assert_eq!(acc.len(), a.len());
    acc.iter_mut()
        .zip(a)
        .for_each(|(acc, &a)| *acc = modulus.reduce_mul_add(a, scalar, *acc));
}

/// Lazily adds the element-wise product `a * b` into `acc`.
#[inline]
pub fn lazy_reduce_add_mul_slice_assign<T, M>(modulus: M, acc: &mut [T], a: &[T], b: &[T])
where
    T: FheUint,
    M: Copy + LazyReduceMulAdd<T, Output = T>,
{
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    acc.iter_mut()
        .zip(a)
        .zip(b)
        .for_each(|((acc, &a), &b)| *acc = modulus.lazy_reduce_mul_add(a, b, *acc));
}

/// Lazily subtracts the element-wise product `a * b` from `acc`.
#[inline]
pub fn lazy_reduce_sub_mul_slice_assign<T, M>(modulus: M, acc: &mut [T], a: &[T], b: &[T])
where
    T: FheUint,
    M: Copy + Modulus<ValueT = T> + ReduceMul<T, Output = T>,
{
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    let m = unsafe { modulus.value_unchecked() };
    acc.iter_mut().zip(a).zip(b).for_each(|((acc, &a), &b)| {
        let prod = modulus.reduce_mul(a, b);
        *acc = acc.wrapping_add(m - prod);
    });
}

/// Writes the lazy element-wise value `a * b + c` into `output`.
#[inline]
pub fn lazy_reduce_mul_add_slice_to<T, M>(modulus: M, a: &[T], b: &[T], c: &[T], output: &mut [T])
where
    T: FheUint,
    M: Copy + LazyReduceMulAdd<T, Output = T>,
{
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());
    a.iter()
        .zip(b)
        .zip(c)
        .zip(output)
        .for_each(|(((&a, &b), &c), o)| *o = modulus.lazy_reduce_mul_add(a, b, c));
}

/// Lazily adds the element-wise product `a * scalar` into `acc`.
#[inline]
pub fn lazy_reduce_add_mul_scalar_slice_assign<T, M>(modulus: M, acc: &mut [T], a: &[T], scalar: T)
where
    T: FheUint,
    M: Copy + LazyReduceMulAdd<T, Output = T>,
{
    debug_assert_eq!(acc.len(), a.len());
    acc.iter_mut()
        .zip(a)
        .for_each(|(x, &y)| *x = modulus.lazy_reduce_mul_add(y, scalar, *x));
}

/// Writes the lazy element-wise value `a * scalar + c` into `output`.
#[inline]
pub fn lazy_reduce_mul_scalar_add_slice_to<T, M>(
    modulus: M,
    a: &[T],
    scalar: T,
    c: &[T],
    output: &mut [T],
) where
    T: FheUint,
    M: Copy + LazyReduceMulAdd<T, Output = T>,
{
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());
    a.iter()
        .zip(c)
        .zip(output)
        .for_each(|((&a, &c), o)| *o = modulus.lazy_reduce_mul_add(a, scalar, c));
}

/// `c += a * b` on a double-word accumulator.
#[inline]
pub fn multiply_add<T: UnsignedInteger>(c: &mut [T; 2], a: T, b: T) {
    let (lw, hw) = a.widening_mul(b);
    let carry;
    (c[0], carry) = c[0].overflowing_add(lw);
    (c[1], _) = c[1].carrying_add(hw, carry);
}

/// Computes the dot product of `a` and `b` modulo `modulus`.
#[inline]
pub fn reduce_dot_product<T, M>(modulus: M, a: &[T], b: &[T]) -> T
where
    T: UnsignedInteger,
    M: Copy + Reduce<[T; 2], Output = T> + ReduceAdd<T, Output = T>,
{
    debug_assert_eq!(a.len(), b.len(), "reduce_dot_product: length mismatch");

    let mut a_iter = a.chunks_exact(DOT_PRODUCT_INNER_CHUNK);
    let mut b_iter = b.chunks_exact(DOT_PRODUCT_INNER_CHUNK);

    let inter = (&mut a_iter)
        .zip(&mut b_iter)
        .map(|(a_s, b_s)| {
            let mut c: [T; 2] = [T::ZERO, T::ZERO];
            for (&a, &b) in a_s.iter().zip(b_s) {
                multiply_add(&mut c, a, b);
            }
            modulus.reduce(c)
        })
        .fold(T::ZERO, |acc: T, b| modulus.reduce_add(acc, b));

    let mut c: [T; 2] = [T::ZERO, T::ZERO];
    a_iter
        .remainder()
        .iter()
        .zip(b_iter.remainder())
        .for_each(|(&a, &b)| {
            multiply_add(&mut c, a, b);
        });
    modulus.reduce_add(modulus.reduce(c), inter)
}

/// Computes the dot product of two iterators modulo `modulus`.
#[inline]
pub fn reduce_dot_product_iter<T, M>(
    modulus: M,
    a: impl IntoIterator<Item = T>,
    b: impl IntoIterator<Item = T>,
) -> T
where
    T: FheUint,
    M: Copy + Reduce<[T; 2], Output = T> + ReduceAddAssign<T>,
{
    let mut a_iter = a.into_iter();
    let mut b_iter = b.into_iter();

    let mut a_temp_array = [T::ZERO; DOT_PRODUCT_INNER_CHUNK];
    let mut b_temp_array = [T::ZERO; DOT_PRODUCT_INNER_CHUNK];

    let mut i = 0;
    let mut result = T::ZERO;

    while let (Some(a_next), Some(b_next)) = (a_iter.next(), b_iter.next()) {
        if i < DOT_PRODUCT_INNER_CHUNK {
            a_temp_array[i] = a_next;
            b_temp_array[i] = b_next;
            i += 1;
        } else {
            let mut c: [T; 2] = [T::ZERO, T::ZERO];
            for (&a, b) in a_temp_array.iter().zip(b_temp_array) {
                multiply_add(&mut c, a, b);
            }
            modulus.reduce_add_assign(&mut result, modulus.reduce(c));

            a_temp_array.fill(T::ZERO);
            b_temp_array.fill(T::ZERO);
            a_temp_array[0] = a_next;
            b_temp_array[0] = b_next;
            i = 1;
        }
    }

    let mut c: [T; 2] = [T::ZERO, T::ZERO];
    for (&a, &b) in a_temp_array[..i].iter().zip(b_temp_array[..i].iter()) {
        multiply_add(&mut c, a, b);
    }
    modulus.reduce_add_assign(&mut result, modulus.reduce(c));

    result
}
