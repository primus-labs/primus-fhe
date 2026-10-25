use core::simd::{Simd, num::SimdUint};

use super::CarryingMul;

macro_rules! simd_uint_carrying_mul_impl {
    ($T:ty, $W:ty, $Bits:literal) => {
        impl<const N: usize> CarryingMul for Simd<$T, N> {
            #[inline]
            fn carrying_mul(self, rhs: Self, carry: Self) -> (Self, Self) {
                let wide = self.cast::<$W>() * rhs.cast::<$W>() + carry.cast::<$W>();
                (wide.cast(), (wide >> $Bits).cast())
            }

            #[inline]
            fn carrying_mul_add(self, rhs: Self, carry: Self, add: Self) -> (Self, Self) {
                let wide =
                    self.cast::<$W>() * rhs.cast::<$W>() + carry.cast::<$W>() + add.cast::<$W>();
                (wide.cast(), (wide >> $Bits).cast())
            }

            #[inline]
            fn carrying_mul_hw(self, rhs: Self, carry: Self) -> Self {
                let wide = self.cast::<$W>() * rhs.cast::<$W>() + carry.cast::<$W>();
                (wide >> $Bits).cast()
            }

            #[inline]
            fn carrying_mul_add_hw(self, rhs: Self, carry: Self, add: Self) -> Self {
                let wide =
                    self.cast::<$W>() * rhs.cast::<$W>() + carry.cast::<$W>() + add.cast::<$W>();
                (wide >> $Bits).cast()
            }
        }
    };
}

simd_uint_carrying_mul_impl! {u8, u16, 8}
simd_uint_carrying_mul_impl! {u16, u32, 16}
simd_uint_carrying_mul_impl! {u32, u64, 32}

macro_rules! simd_uint_carrying_mul_large {
    ($T:ty, $Half:literal) => {
        impl<const N: usize> CarryingMul for Simd<$T, N> {
            #[inline]
            fn carrying_mul(self, rhs: Self, carry: Self) -> (Self, Self) {
                let lower_mask = Self::splat(!0 >> $Half);
                let half = Self::splat($Half);

                let a_low = self & lower_mask;
                let a_high = self >> half;
                let b_low = rhs & lower_mask;
                let b_high = rhs >> half;
                let carry_low = carry & lower_mask;
                let carry_high = carry >> half;

                let w0 = a_low * b_low + carry_low;
                let w1 = a_low * b_high + carry_high;
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
            fn carrying_mul_add(self, rhs: Self, carry: Self, add: Self) -> (Self, Self) {
                let lower_mask = Self::splat(!0 >> $Half);
                let half = Self::splat($Half);

                let a_low = self & lower_mask;
                let a_high = self >> half;
                let b_low = rhs & lower_mask;
                let b_high = rhs >> half;
                let carry_low = carry & lower_mask;
                let carry_high = carry >> half;
                let add_low = add & lower_mask;
                let add_high = add >> half;

                let w0 = a_low * b_low + carry_low + add_low;
                let w1 = a_low * b_high + carry_high;
                let w2 = a_high * b_low + add_high;
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
            fn carrying_mul_hw(self, rhs: Self, carry: Self) -> Self {
                let lower_mask = Self::splat(!0 >> $Half);
                let half = Self::splat($Half);

                let a_low = self & lower_mask;
                let a_high = self >> half;
                let b_low = rhs & lower_mask;
                let b_high = rhs >> half;
                let carry_low = carry & lower_mask;
                let carry_high = carry >> half;

                let w0 = a_low * b_low + carry_low;
                let w1 = a_low * b_high + carry_high;
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

            #[inline]
            fn carrying_mul_add_hw(self, rhs: Self, carry: Self, add: Self) -> Self {
                let lower_mask = Self::splat(!0 >> $Half);
                let half = Self::splat($Half);

                let a_low = self & lower_mask;
                let a_high = self >> half;
                let b_low = rhs & lower_mask;
                let b_high = rhs >> half;
                let carry_low = carry & lower_mask;
                let carry_high = carry >> half;
                let add_low = add & lower_mask;
                let add_high = add >> half;

                let w0 = a_low * b_low + carry_low + add_low;
                let w1 = a_low * b_high + carry_high;
                let w2 = a_high * b_low + add_high;
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

simd_uint_carrying_mul_large! {u64, 32}

#[cfg(target_pointer_width = "32")]
simd_uint_carrying_mul_impl! {usize, u64, 32}
#[cfg(target_pointer_width = "64")]
simd_uint_carrying_mul_large! {usize, 32}
