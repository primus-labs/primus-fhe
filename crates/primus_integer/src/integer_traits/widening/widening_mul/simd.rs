use core::simd::{Simd, num::SimdUint};

use super::WideningMul;

macro_rules! impl_simd_uint_widening_mul {
    ($T:ty, $W:ty, $Bits:literal) => {
        impl<const N: usize> WideningMul for Simd<$T, N> {
            #[inline]
            fn widening_mul(self, rhs: Self) -> (Self, Self) {
                let wide = self.cast::<$W>() * rhs.cast::<$W>();
                (wide.cast(), (wide >> $Bits).cast())
            }

            #[inline]
            fn widening_mul_hw(self, rhs: Self) -> Self {
                let wide = self.cast::<$W>() * rhs.cast::<$W>();
                (wide >> $Bits).cast()
            }
        }
    };
}

impl_simd_uint_widening_mul! {u8, u16, 8}
impl_simd_uint_widening_mul! {u16, u32, 16}
impl_simd_uint_widening_mul! {u32, u64, 32}

// This code is a translation of the __mulddi3 function in LLVM's
// compiler-rt. It is an optimized variant of the common method
// `(a + b) * (c + d) = ac + ad + bc + bd`.
//
// For some reason LLVM can optimize the C version very well, but
// keeps shuffling registers in this Rust translation.
macro_rules! simd_uint_widening_mul_large {
    ($T:ty, $Half:literal) => {
        impl<const N: usize> WideningMul for ::core::simd::Simd<$T, N> {
            #[inline]
            fn widening_mul(self, rhs: Self) -> (Self, Self) {
                let lower_mask = Self::splat(!0 >> $Half);
                let half = Self::splat($Half);

                let a_low = self & lower_mask;
                let a_high = self >> half;
                let b_low = rhs & lower_mask;
                let b_high = rhs >> half;

                let w0 = a_low * b_low;
                let w1 = a_low * b_high;
                let w2 = a_high * b_low;
                let w3 = a_high * b_high;

                let w0l = w0 & lower_mask;
                let w0h = w0 >> half;

                let s1 = w1 + w0h;
                let s1l = s1 & lower_mask;
                let s1h = s1 >> half;

                let s2 = s1l + w2;
                let s2l = s2 << half;
                let s2h = s2 >> half;

                let hi1 = w3 + s1h + s2h;

                let lo1 = s2l + w0l;

                (lo1, hi1)
            }

            #[inline]
            fn widening_mul_hw(self, rhs: Self) -> Self {
                let lower_mask = Self::splat(!0 >> $Half);
                let half = Self::splat($Half);

                let a_low = self & lower_mask;
                let a_high = self >> half;
                let b_low = rhs & lower_mask;
                let b_high = rhs >> half;

                let w0 = a_low * b_low;
                let w1 = a_low * b_high;
                let w2 = a_high * b_low;
                let w3 = a_high * b_high;

                let w0h = w0 >> half;

                let s1 = w1 + w0h;
                let s1l = s1 & lower_mask;
                let s1h = s1 >> half;

                let s2 = s1l + w2;
                let s2h = s2 >> half;

                let hi1 = w3 + s1h + s2h;

                hi1
            }
        }
    };
}

simd_uint_widening_mul_large! {u64, 32}

#[cfg(target_pointer_width = "32")]
impl_simd_uint_widening_mul! {usize, u64, 32}
#[cfg(target_pointer_width = "64")]
simd_uint_widening_mul_large! { usize, 32 }
