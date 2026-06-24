use std::simd::cmp::SimdOrd;

use primus_integer::{SimdArray, SimdUnsignedInteger};

use crate::{FactorMul, LazyFactorMul};

use super::slice;

#[inline]
pub(crate) fn lazy_factor_mul_slice_assign<T, F, SF>(factor: F, values: &mut [T], modulus: T)
where
    T: SimdUnsignedInteger,
    F: Copy + LazyFactorMul<T> + Into<SF>,
    SF: Copy + LazyFactorMul<T::SimdT>,
{
    let simd_factor: SF = factor.into();
    let simd_modulus = T::SimdT::splat(modulus);

    let (chunks, remainder) = T::simd_as_chunks_mut(values);

    for chunk in chunks {
        let value = T::SimdT::from_array(*chunk);
        *chunk = simd_factor
            .lazy_factor_mul_modulo(value, simd_modulus)
            .to_array();
    }

    slice::lazy_factor_mul_slice_assign(factor, remainder, modulus);
}

#[inline]
pub(crate) fn lazy_factor_mul_slice_to<T, F, SF>(
    factor: F,
    input: &[T],
    output: &mut [T],
    modulus: T,
) where
    T: SimdUnsignedInteger,
    F: Copy + LazyFactorMul<T> + Into<SF>,
    SF: Copy + LazyFactorMul<T::SimdT>,
{
    debug_assert_eq!(input.len(), output.len());

    let simd_factor: SF = factor.into();
    let simd_modulus = T::SimdT::splat(modulus);

    let (input_chunks, input_rem) = T::simd_as_chunks(input);
    let (output_chunks, output_rem) = T::simd_as_chunks_mut(output);

    for (input, output) in input_chunks.iter().zip(output_chunks) {
        let value = T::SimdT::from_array(*input);
        *output = simd_factor
            .lazy_factor_mul_modulo(value, simd_modulus)
            .to_array();
    }

    slice::lazy_factor_mul_slice_to(factor, input_rem, output_rem, modulus);
}

#[inline]
pub(crate) fn factor_mul_slice_assign<T, F, SF>(factor: F, values: &mut [T], modulus: T)
where
    T: SimdUnsignedInteger,
    F: Copy + FactorMul<T> + Into<SF>,
    SF: Copy + FactorMul<T::SimdT>,
{
    let simd_factor: SF = factor.into();
    let simd_modulus = T::SimdT::splat(modulus);

    let (chunks, remainder) = T::simd_as_chunks_mut(values);

    for chunk in chunks {
        let value = T::SimdT::from_array(*chunk);
        *chunk = simd_factor
            .factor_mul_modulo(value, simd_modulus)
            .to_array();
    }

    slice::factor_mul_slice_assign(factor, remainder, modulus);
}

#[inline]
pub(crate) fn factor_mul_slice_to<T, F, SF>(factor: F, input: &[T], output: &mut [T], modulus: T)
where
    T: SimdUnsignedInteger,
    F: Copy + FactorMul<T> + Into<SF>,
    SF: Copy + FactorMul<T::SimdT>,
{
    debug_assert_eq!(input.len(), output.len());

    let simd_factor: SF = factor.into();
    let simd_modulus = T::SimdT::splat(modulus);

    let (input_chunks, input_rem) = T::simd_as_chunks(input);
    let (output_chunks, output_rem) = T::simd_as_chunks_mut(output);

    for (input, output) in input_chunks.iter().zip(output_chunks) {
        let value = T::SimdT::from_array(*input);
        *output = simd_factor
            .factor_mul_modulo(value, simd_modulus)
            .to_array();
    }

    slice::factor_mul_slice_to(factor, input_rem, output_rem, modulus);
}

#[inline]
pub(crate) fn add_factor_mul_slice_assign<T, F, SF>(factor: F, acc: &mut [T], rhs: &[T], modulus: T)
where
    T: SimdUnsignedInteger,
    F: Copy + FactorMul<T> + Into<SF>,
    SF: Copy + FactorMul<T::SimdT>,
{
    debug_assert_eq!(acc.len(), rhs.len());

    let simd_factor: SF = factor.into();
    let simd_modulus = T::SimdT::splat(modulus);

    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (rhs_chunks, rhs_rem) = T::simd_as_chunks(rhs);
    for (acc, rhs) in acc_chunks.iter_mut().zip(rhs_chunks) {
        let acc_value = T::SimdT::from_array(*acc);
        let rhs_value = T::SimdT::from_array(*rhs);

        let product = simd_factor.factor_mul_modulo(rhs_value, simd_modulus);

        let sum = acc_value + product;
        *acc = sum.simd_min(sum - simd_modulus).to_array();
    }

    slice::add_factor_mul_slice_assign(factor, acc_rem, rhs_rem, modulus);
}

#[inline]
pub(crate) fn sub_factor_mul_slice_assign<T, F, SF>(factor: F, acc: &mut [T], rhs: &[T], modulus: T)
where
    T: SimdUnsignedInteger,
    F: Copy + FactorMul<T> + Into<SF>,
    SF: Copy + FactorMul<T::SimdT>,
{
    debug_assert_eq!(acc.len(), rhs.len());

    let simd_factor: SF = factor.into();
    let simd_modulus = T::SimdT::splat(modulus);

    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (rhs_chunks, rhs_rem) = T::simd_as_chunks(rhs);

    for (acc, rhs) in acc_chunks.iter_mut().zip(rhs_chunks) {
        let acc_value = T::SimdT::from_array(*acc);
        let rhs_value = T::SimdT::from_array(*rhs);

        let product = simd_factor.factor_mul_modulo(rhs_value, simd_modulus);

        let diff = acc_value - product;
        *acc = diff.simd_min(diff + simd_modulus).to_array();
    }

    slice::sub_factor_mul_slice_assign(factor, acc_rem, rhs_rem, modulus);
}

#[inline]
pub(crate) fn factor_mul_add_slice_to<T, F, SF>(
    factor: F,
    rhs: &[T],
    addend: &[T],
    output: &mut [T],
    modulus: T,
) where
    T: SimdUnsignedInteger,
    F: Copy + FactorMul<T> + Into<SF>,
    SF: Copy + FactorMul<T::SimdT>,
{
    debug_assert_eq!(rhs.len(), addend.len());
    debug_assert_eq!(rhs.len(), output.len());

    let simd_factor: SF = factor.into();
    let simd_modulus = T::SimdT::splat(modulus);

    let (rhs_chunks, rhs_rem) = T::simd_as_chunks(rhs);
    let (addend_chunks, addend_rem) = T::simd_as_chunks(addend);
    let (output_chunks, output_rem) = T::simd_as_chunks_mut(output);
    for ((rc, ac), oc) in rhs_chunks.iter().zip(addend_chunks).zip(output_chunks) {
        let rv = T::SimdT::from_array(*rc);
        let av = T::SimdT::from_array(*ac);
        let product = simd_factor.factor_mul_modulo(rv, simd_modulus);

        let sum = product + av;
        *oc = sum.simd_min(sum - simd_modulus).to_array();
    }

    slice::factor_mul_add_slice_to(factor, rhs_rem, addend_rem, output_rem, modulus);
}
