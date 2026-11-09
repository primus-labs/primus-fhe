use primus_integer::FheUint;

use crate::{FactorSliceOps, LazyFactorSliceOps, ShoupFactor};

use crate::common::slice;

use super::native;

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
        if native::try_mul_assign(self, values, modulus) {
            return;
        }
        slice::factor_mul_slice_assign(self, values, modulus);
    }

    #[inline]
    fn factor_mul_slice_to(self, input: &[T], output: &mut [T], modulus: T) {
        if native::try_mul_to(self, input, output, modulus) {
            return;
        }
        slice::factor_mul_slice_to(self, input, output, modulus);
    }

    #[inline]
    fn add_factor_mul_slice_assign(self, acc: &mut [T], rhs: &[T], modulus: T) {
        if native::try_add_mul_assign(self, acc, rhs, modulus) {
            return;
        }
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
        if native::try_mul_assign(self, values, modulus) {
            return;
        }
        // For 64-bit in-place products, let LLVM choose the loop shape instead
        // of imposing fixed SIMD chunks. The word-width choice folds at compile time.
        if T::BITS == 64 {
            slice::factor_mul_slice_assign(self, values, modulus);
        } else {
            simd::factor_mul_slice_assign::<T, ShoupFactor<T>, SimdShoupFactor<T>>(
                self, values, modulus,
            );
        }
    }

    #[inline]
    fn factor_mul_slice_to(self, input: &[T], output: &mut [T], modulus: T) {
        if native::try_mul_to(self, input, output, modulus) {
            return;
        }
        simd::factor_mul_slice_to::<T, ShoupFactor<T>, SimdShoupFactor<T>>(
            self, input, output, modulus,
        );
    }

    #[inline]
    fn add_factor_mul_slice_assign(self, acc: &mut [T], rhs: &[T], modulus: T) {
        if native::try_add_mul_assign(self, acc, rhs, modulus) {
            return;
        }
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
