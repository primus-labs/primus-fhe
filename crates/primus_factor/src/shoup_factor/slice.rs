use primus_integer::FheUint;

use crate::{FactorSliceOps, LazyFactorSliceOps, ShoupFactor};

#[cfg(not(feature = "simd"))]
use crate::common::slice;

#[cfg(not(feature = "simd"))]
impl<T: FheUint> LazyFactorSliceOps<T> for ShoupFactor<T> {
    #[inline]
    fn lazy_factor_mul_slice_assign(self, values: &mut [T], modulus: T) {
        slice::lazy_factor_mul_slice_assign(self, values, modulus);
    }

    #[inline]
    fn lazy_factor_mul_slice_to(self, input: &[T], output: &mut [T], modulus: T) {
        slice::lazy_factor_mul_slice_to(self, input, output, modulus);
    }
}

#[cfg(not(feature = "simd"))]
impl<T: FheUint> FactorSliceOps<T> for ShoupFactor<T> {
    #[inline]
    fn factor_mul_slice_assign(self, values: &mut [T], modulus: T) {
        slice::factor_mul_slice_assign(self, values, modulus);
    }

    #[inline]
    fn factor_mul_slice_to(self, input: &[T], output: &mut [T], modulus: T) {
        slice::factor_mul_slice_to(self, input, output, modulus);
    }

    #[inline]
    fn add_factor_mul_slice_assign(self, acc: &mut [T], rhs: &[T], modulus: T) {
        slice::add_factor_mul_slice_assign(self, acc, rhs, modulus);
    }

    #[inline]
    fn sub_factor_mul_slice_assign(self, acc: &mut [T], rhs: &[T], modulus: T) {
        slice::sub_factor_mul_slice_assign(self, acc, rhs, modulus);
    }

    #[inline]
    fn factor_mul_add_slice_to(self, rhs: &[T], addend: &[T], output: &mut [T], modulus: T) {
        slice::factor_mul_add_slice_to(self, rhs, addend, output, modulus);
    }
}

#[cfg(feature = "simd")]
use crate::{SimdShoupFactor, common::simd};

#[cfg(feature = "simd")]
impl<T: FheUint> LazyFactorSliceOps<T> for ShoupFactor<T> {
    #[inline]
    fn lazy_factor_mul_slice_assign(self, values: &mut [T], modulus: T) {
        simd::lazy_factor_mul_slice_assign::<T, ShoupFactor<T>, SimdShoupFactor<T>>(
            self, values, modulus,
        );
    }

    #[inline]
    fn lazy_factor_mul_slice_to(self, input: &[T], output: &mut [T], modulus: T) {
        simd::lazy_factor_mul_slice_to::<T, ShoupFactor<T>, SimdShoupFactor<T>>(
            self, input, output, modulus,
        );
    }
}

#[cfg(feature = "simd")]
impl<T: FheUint> FactorSliceOps<T> for ShoupFactor<T> {
    #[inline]
    fn factor_mul_slice_assign(self, values: &mut [T], modulus: T) {
        simd::factor_mul_slice_assign::<T, ShoupFactor<T>, SimdShoupFactor<T>>(
            self, values, modulus,
        );
    }

    #[inline]
    fn factor_mul_slice_to(self, input: &[T], output: &mut [T], modulus: T) {
        simd::factor_mul_slice_to::<T, ShoupFactor<T>, SimdShoupFactor<T>>(
            self, input, output, modulus,
        );
    }

    #[inline]
    fn add_factor_mul_slice_assign(self, acc: &mut [T], rhs: &[T], modulus: T) {
        simd::add_factor_mul_slice_assign::<T, ShoupFactor<T>, SimdShoupFactor<T>>(
            self, acc, rhs, modulus,
        );
    }

    #[inline]
    fn sub_factor_mul_slice_assign(self, acc: &mut [T], rhs: &[T], modulus: T) {
        simd::sub_factor_mul_slice_assign::<T, ShoupFactor<T>, SimdShoupFactor<T>>(
            self, acc, rhs, modulus,
        );
    }

    #[inline]
    fn factor_mul_add_slice_to(self, rhs: &[T], addend: &[T], output: &mut [T], modulus: T) {
        simd::factor_mul_add_slice_to::<T, ShoupFactor<T>, SimdShoupFactor<T>>(
            self, rhs, addend, output, modulus,
        );
    }
}
