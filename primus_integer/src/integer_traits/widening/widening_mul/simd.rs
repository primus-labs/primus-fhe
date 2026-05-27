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

#[cfg(test)]
mod tests {
    use core::fmt::Debug;
    use core::simd::{Simd, SimdElement};

    use rand::distr::{Distribution, StandardUniform};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    fn test_widen_mul_per_type_lane_count<T, const N: usize>()
    where
        T: SimdElement + WideningMul + PartialEq + Debug,
        Simd<T, N>: WideningMul,
        StandardUniform: Distribution<Simd<T, N>>,
    {
        let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0000_0003);

        let l: Simd<T, N> = StandardUniform.sample(&mut rng);
        let r: Simd<T, N> = StandardUniform.sample(&mut rng);

        let l_arr = l.to_array();
        let r_arr = r.to_array();

        let (lw, hw) = l.widening_mul(r);
        let lw_arr = lw.as_array();
        let hw_arr = hw.as_array();
        for i in 0..N {
            assert_eq!(
                l_arr[i].widening_mul(r_arr[i]),
                (lw_arr[i], hw_arr[i]),
                "lane {i}: l={:?} r={:?}",
                l_arr[i],
                r_arr[i],
            );
        }
    }

    fn test_widen_mul_per_type<T>()
    where
        T: SimdElement + WideningMul + PartialEq + Debug,
        Simd<T, 1>: WideningMul,
        Simd<T, 2>: WideningMul,
        Simd<T, 4>: WideningMul,
        Simd<T, 8>: WideningMul,
        Simd<T, 16>: WideningMul,
        Simd<T, 32>: WideningMul,
        Simd<T, 64>: WideningMul,
        StandardUniform: Distribution<Simd<T, 1>>
            + Distribution<Simd<T, 2>>
            + Distribution<Simd<T, 4>>
            + Distribution<Simd<T, 8>>
            + Distribution<Simd<T, 16>>
            + Distribution<Simd<T, 32>>
            + Distribution<Simd<T, 64>>,
    {
        test_widen_mul_per_type_lane_count::<T, 1>();
        test_widen_mul_per_type_lane_count::<T, 2>();
        test_widen_mul_per_type_lane_count::<T, 4>();
        test_widen_mul_per_type_lane_count::<T, 8>();
        test_widen_mul_per_type_lane_count::<T, 16>();
        test_widen_mul_per_type_lane_count::<T, 32>();
        test_widen_mul_per_type_lane_count::<T, 64>();
    }

    #[test]
    fn test_widen_mul() {
        test_widen_mul_per_type::<u8>();
        test_widen_mul_per_type::<u16>();
        test_widen_mul_per_type::<u32>();
        test_widen_mul_per_type::<u64>();
    }
}
