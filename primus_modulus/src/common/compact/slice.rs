use primus_integer::UnsignedInteger;

pub use crate::common::uint::slice::{
    reduce_inv_slice_assign, reduce_inv_slice_to, reduce_neg_slice_assign, reduce_neg_slice_to,
    reduce_once_slice_assign, reduce_once_slice_to, try_reduce_inv_slice_assign,
    try_reduce_inv_slice_to,
};

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
