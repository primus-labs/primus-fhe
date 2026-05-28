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

#[cfg(test)]
mod tests {
    use core::{
        fmt::Debug,
        simd::{Simd, SimdElement},
    };

    use rand::distr::{Distribution, StandardUniform};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    fn test_carry_mul_per_type_lane_count<T, const N: usize>()
    where
        T: SimdElement + CarryingMul + PartialEq + Debug,
        Simd<T, N>: CarryingMul,
        StandardUniform: Distribution<Simd<T, N>>,
    {
        let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0000_0004);

        let l: Simd<T, N> = StandardUniform.sample(&mut rng);
        let r: Simd<T, N> = StandardUniform.sample(&mut rng);
        let carry: Simd<T, N> = StandardUniform.sample(&mut rng);
        let add: Simd<T, N> = StandardUniform.sample(&mut rng);

        let l_arr = l.to_array();
        let r_arr = r.to_array();
        let carry_arr = carry.to_array();
        let add_arr = add.to_array();

        let (lw, hw) = l.carrying_mul(r, carry);
        let lw_arr = lw.as_array();
        let hw_arr = hw.as_array();
        for i in 0..N {
            assert_eq!(
                CarryingMul::carrying_mul(l_arr[i], r_arr[i], carry_arr[i]),
                (lw_arr[i], hw_arr[i]),
                "lane {i}: l={:?} r={:?} carry={:?}",
                l_arr[i],
                r_arr[i],
                carry_arr[i],
            );
        }

        let (lw, hw) = l.carrying_mul_add(r, carry, add);
        let lw_arr = lw.as_array();
        let hw_arr = hw.as_array();
        for i in 0..N {
            assert_eq!(
                CarryingMul::carrying_mul_add(l_arr[i], r_arr[i], carry_arr[i], add_arr[i]),
                (lw_arr[i], hw_arr[i]),
                "lane {i}: l={:?} r={:?} carry={:?} add={:?}",
                l_arr[i],
                r_arr[i],
                carry_arr[i],
                add_arr[i]
            );
        }
    }

    fn test_carry_mul_per_type<T>()
    where
        T: SimdElement + CarryingMul + PartialEq + Debug,
        Simd<T, 1>: CarryingMul,
        Simd<T, 2>: CarryingMul,
        Simd<T, 4>: CarryingMul,
        Simd<T, 8>: CarryingMul,
        Simd<T, 16>: CarryingMul,
        Simd<T, 32>: CarryingMul,
        Simd<T, 64>: CarryingMul,
        StandardUniform: Distribution<Simd<T, 1>>
            + Distribution<Simd<T, 2>>
            + Distribution<Simd<T, 4>>
            + Distribution<Simd<T, 8>>
            + Distribution<Simd<T, 16>>
            + Distribution<Simd<T, 32>>
            + Distribution<Simd<T, 64>>,
    {
        test_carry_mul_per_type_lane_count::<T, 1>();
        test_carry_mul_per_type_lane_count::<T, 2>();
        test_carry_mul_per_type_lane_count::<T, 4>();
        test_carry_mul_per_type_lane_count::<T, 8>();
        test_carry_mul_per_type_lane_count::<T, 16>();
        test_carry_mul_per_type_lane_count::<T, 32>();
        test_carry_mul_per_type_lane_count::<T, 64>();
    }

    #[test]
    fn test_carry_mul() {
        test_carry_mul_per_type::<u8>();
        test_carry_mul_per_type::<u16>();
        test_carry_mul_per_type::<u32>();
        test_carry_mul_per_type::<u64>();
    }
}
