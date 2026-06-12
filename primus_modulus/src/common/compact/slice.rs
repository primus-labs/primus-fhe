use primus_integer::{FheUint, UnsignedInteger};
use primus_reduce::{Modulus, prelude::*};

pub use crate::common::uint::slice::{
    reduce_inv_slice_assign, reduce_inv_slice_to, reduce_neg_slice_assign, reduce_neg_slice_to,
    reduce_once_slice_assign, reduce_once_slice_to, try_reduce_inv_slice_assign,
    try_reduce_inv_slice_to,
};

use super::DOT_PRODUCT_INNER_CHUNK;

#[inline]
pub fn reduce_add_slice_assign<T: UnsignedInteger>(modulus: T, a: &mut [T], b: &[T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter_mut()
        .zip(b)
        .for_each(|(x, &y)| super::reduce_add_assign(modulus, x, y));
}
#[inline]
pub fn reduce_add_slice_to<T: UnsignedInteger>(modulus: T, a: &[T], b: &[T], output: &mut [T]) {
    debug_assert_eq!(output.len(), a.len());
    debug_assert_eq!(output.len(), b.len());
    output.iter_mut().zip(a).zip(b).for_each(|((out, &x), &y)| {
        *out = super::reduce_add(modulus, x, y);
    });
}

#[inline]
pub fn reduce_sub_slice_assign<T: UnsignedInteger>(modulus: T, a: &mut [T], b: &[T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter_mut()
        .zip(b)
        .for_each(|(x, &y)| super::reduce_sub_assign(modulus, x, y));
}
#[inline]
pub fn reduce_sub_slice_to<T: UnsignedInteger>(modulus: T, a: &[T], b: &[T], output: &mut [T]) {
    debug_assert_eq!(output.len(), a.len());
    debug_assert_eq!(output.len(), b.len());
    output.iter_mut().zip(a).zip(b).for_each(|((out, &x), &y)| {
        *out = super::reduce_sub(modulus, x, y);
    });
}
#[inline]
pub fn reduce_sub_slice_rev_assign<T: UnsignedInteger>(modulus: T, a: &[T], b: &mut [T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter_mut())
        .for_each(|(&x, y)| *y = super::reduce_sub(modulus, x, *y));
}

#[inline]
pub fn reduce_double_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|v| super::reduce_double_assign(modulus, v));
}
#[inline]
pub fn reduce_double_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::reduce_double(modulus, y));
}

#[inline]
pub fn lazy_reduce_sub_slice_assign<T: UnsignedInteger>(modulus: T, a: &mut [T], b: &[T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter_mut()
        .zip(b)
        .for_each(|(x, &y)| super::lazy_reduce_sub_assign(modulus, x, y));
}
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
#[inline]
pub fn lazy_reduce_sub_slice_rev_assign<T: UnsignedInteger>(modulus: T, a: &[T], b: &mut [T]) {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter_mut())
        .for_each(|(&x, y)| *y = super::lazy_reduce_sub(modulus, x, *y));
}

#[inline]
pub fn lazy_reduce_neg_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|value| super::lazy_reduce_neg_assign(modulus, value));
}

#[inline]
pub fn lazy_reduce_neg_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::lazy_reduce_neg(modulus, y));
}

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

#[inline]
pub fn reduce_mul_scalar_slice_assign<T, M>(modulus: M, a: &mut [T], scalar: T)
where
    T: FheUint,
    M: Copy + ReduceMulAssign<T>,
{
    a.iter_mut()
        .for_each(|a| modulus.reduce_mul_assign(a, scalar));
}

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

#[inline]
pub fn lazy_reduce_mul_scalar_slice_assign<T, M>(modulus: M, a: &mut [T], scalar: T)
where
    T: FheUint,
    M: Copy + LazyReduceMulAssign<T>,
{
    a.iter_mut()
        .for_each(|a| modulus.lazy_reduce_mul_assign(a, scalar));
}

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
