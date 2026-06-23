use core::iter::zip;

use primus_integer::UnsignedInteger;

use crate::{FactorMul, LazyFactorMul};

#[inline]
fn reduce_add<T: UnsignedInteger>(a: T, b: T, modulus: T) -> T {
    let sum = a + b;
    // `a, b ∈ [0, m)` ⇒ `sum ∈ [0, 2m)`. Same `min` trick as `factor_mul_modulo`.
    sum.min(sum.wrapping_sub(modulus))
}

#[inline]
pub(crate) fn lazy_factor_mul_slice_assign<T, F>(factor: F, values: &mut [T], modulus: T)
where
    T: UnsignedInteger,
    F: Copy + LazyFactorMul<T>,
{
    for value in values {
        *value = factor.lazy_factor_mul_modulo(*value, modulus)
    }
}

#[inline]
pub(crate) fn lazy_factor_mul_slice_to<T, F>(factor: F, input: &[T], output: &mut [T], modulus: T)
where
    T: UnsignedInteger,
    F: Copy + LazyFactorMul<T>,
{
    debug_assert_eq!(input.len(), output.len());
    for (&value, out) in zip(input, output) {
        *out = factor.lazy_factor_mul_modulo(value, modulus)
    }
}

#[inline]
pub(crate) fn factor_mul_slice_assign<T, F>(factor: F, values: &mut [T], modulus: T)
where
    T: UnsignedInteger,
    F: Copy + FactorMul<T>,
{
    for value in values {
        *value = factor.factor_mul_modulo(*value, modulus)
    }
}

#[inline]
pub(crate) fn factor_mul_slice_to<T, F>(factor: F, input: &[T], output: &mut [T], modulus: T)
where
    T: UnsignedInteger,
    F: Copy + FactorMul<T>,
{
    debug_assert_eq!(input.len(), output.len());
    for (&value, out) in zip(input, output) {
        *out = factor.factor_mul_modulo(value, modulus)
    }
}

#[inline]
pub(crate) fn add_factor_mul_slice_assign<T, F>(factor: F, acc: &mut [T], rhs: &[T], modulus: T)
where
    T: UnsignedInteger,
    F: Copy + FactorMul<T>,
{
    debug_assert_eq!(acc.len(), rhs.len());
    for (a, &b) in zip(acc, rhs) {
        *a = reduce_add(*a, factor.factor_mul_modulo(b, modulus), modulus);
    }
}

#[inline]
pub(crate) fn sub_factor_mul_slice_assign<T, F>(factor: F, acc: &mut [T], rhs: &[T], modulus: T)
where
    T: UnsignedInteger,
    F: Copy + FactorMul<T>,
{
    debug_assert_eq!(acc.len(), rhs.len());
    for (a, &b) in zip(acc, rhs) {
        let prod = factor.factor_mul_modulo(b, modulus);
        // `*acc - prod (mod modulus)`. Both are in `[0, modulus)`.
        *a = if *a >= prod {
            *a - prod
        } else {
            a.wrapping_add(modulus).wrapping_sub(prod)
        };
    }
}

#[inline]
pub(crate) fn factor_mul_add_slice_to<T, F>(
    factor: F,
    rhs: &[T],
    addend: &[T],
    output: &mut [T],
    modulus: T,
) where
    T: UnsignedInteger,
    F: Copy + FactorMul<T>,
{
    debug_assert_eq!(rhs.len(), addend.len());
    debug_assert_eq!(rhs.len(), output.len());
    for ((&rhs_value, &addend_value), output) in rhs.iter().zip(addend).zip(output) {
        let prod = factor.factor_mul_modulo(rhs_value, modulus);
        *output = reduce_add(prod, addend_value, modulus);
    }
}
