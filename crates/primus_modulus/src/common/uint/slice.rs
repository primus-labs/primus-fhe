use primus_integer::UnsignedInteger;
use primus_reduce::ReduceError;

/// Reduces each value in place by subtracting `modulus` at most once.
#[inline]
pub fn reduce_once_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|value| super::reduce_once_assign(modulus, value));
}
/// Reduces `input` into `output` by subtracting `modulus` at most once per element.
#[inline]
pub fn reduce_once_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::reduce_once(modulus, y));
}

/// Replaces each value with its additive inverse modulo `modulus`.
#[inline]
pub fn reduce_neg_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|value| super::reduce_neg_assign(modulus, value));
}

/// Writes the additive inverse of each `input` value modulo `modulus` into `output`.
#[inline]
pub fn reduce_neg_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::reduce_neg(modulus, y));
}

/// Adds `b` into `a` element-wise modulo `modulus`.
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
        .zip(b)
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

/// Replaces each value with the lazy additive inverse `modulus - value`.
#[inline]
pub fn lazy_reduce_neg_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|value| super::lazy_reduce_neg_assign(modulus, value));
}

/// Writes the lazy additive inverse of each `input` value into `output`.
#[inline]
pub fn lazy_reduce_neg_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::lazy_reduce_neg(modulus, y));
}

/// Replaces each value with its multiplicative inverse modulo `modulus`.
///
/// # Panics
///
/// Panics if any value has no inverse modulo `modulus`.
#[inline]
pub fn reduce_inv_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|v| super::reduce_inv_assign(modulus, v));
}
/// Writes multiplicative inverses of `input` modulo `modulus` into `output`.
///
/// # Panics
///
/// Panics if any input value has no inverse modulo `modulus`.
#[inline]
pub fn reduce_inv_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::reduce_inv(modulus, y));
}

/// Attempts to invert each value in place modulo `modulus`.
#[inline]
pub fn try_reduce_inv_slice_assign<T: UnsignedInteger>(
    modulus: T,
    values: &mut [T],
) -> Result<(), ReduceError<T>> {
    for (i, v) in values.iter_mut().enumerate() {
        *v = super::try_reduce_inv(modulus, *v).map_err(|_| ReduceError::NoInverseAtIndex {
            index: i,
            value: *v,
            modulus,
        })?;
    }
    Ok(())
}
/// Attempts to write inverses of `input` modulo `modulus` into `output`.
#[inline]
pub fn try_reduce_inv_slice_to<T: UnsignedInteger>(
    modulus: T,
    input: &[T],
    output: &mut [T],
) -> Result<(), ReduceError<T>> {
    debug_assert_eq!(input.len(), output.len());
    for (i, (&y, x)) in input.iter().zip(output.iter_mut()).enumerate() {
        *x = super::try_reduce_inv(modulus, y).map_err(|_| ReduceError::NoInverseAtIndex {
            index: i,
            value: y,
            modulus,
        })?;
    }
    Ok(())
}
