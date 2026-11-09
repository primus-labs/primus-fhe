use core::simd::{Mask, Simd, SimdElement, cmp::SimdPartialOrd, num::SimdInt};

use super::CarryingAdd;

macro_rules! impl_simd_uint_carrying_add {
    ($($T:ty),*) => {
        $(
            impl<const N:usize> CarryingAdd for Simd<$T, N>

            {
                type CarryT = Mask<<$T as SimdElement>::Mask, N>;

                #[inline]
                fn carrying_add(self, rhs: Self, carry: Self::CarryT) -> (Self, Self::CarryT) {
                    let sum = self + rhs;
                    // A true mask lane becomes an all-ones unsigned word, so
                    // subtracting it adds one modulo the word radix.
                    let sum_with_carry = sum - carry.to_simd().cast();
                    let carry_out = sum.simd_lt(self) | sum_with_carry.simd_lt(sum);
                    (sum_with_carry, carry_out)
                }
            }
        )*
    };
}

impl_simd_uint_carrying_add! {u8, u16, u32, u64, usize}
