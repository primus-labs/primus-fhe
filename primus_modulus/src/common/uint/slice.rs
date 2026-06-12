use primus_integer::UnsignedInteger;
use primus_reduce::ReduceError;

#[inline]
pub fn reduce_once_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|value| super::reduce_once_assign(modulus, value));
}
#[inline]
pub fn reduce_once_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::reduce_once(modulus, y));
}

#[inline]
pub fn reduce_neg_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|value| super::reduce_neg_assign(modulus, value));
}

#[inline]
pub fn reduce_neg_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::reduce_neg(modulus, y));
}

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
pub fn reduce_inv_slice_assign<T: UnsignedInteger>(modulus: T, values: &mut [T]) {
    values
        .iter_mut()
        .for_each(|v| super::reduce_inv_assign(modulus, v));
}
#[inline]
pub fn reduce_inv_slice_to<T: UnsignedInteger>(modulus: T, input: &[T], output: &mut [T]) {
    debug_assert_eq!(input.len(), output.len());
    output
        .iter_mut()
        .zip(input)
        .for_each(|(x, &y)| *x = super::reduce_inv(modulus, y));
}

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
