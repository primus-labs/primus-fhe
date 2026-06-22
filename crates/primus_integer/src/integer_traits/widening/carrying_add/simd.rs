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
                    let a = self + rhs;
                    let b = a - carry.to_simd().cast();
                    (b, a.simd_lt(self) | b.simd_lt(a))
                }
            }
        )*
    };
}

impl_simd_uint_carrying_add! {u8, u16, u32, u64, usize}

#[cfg(test)]
mod tests {
    use core::{
        fmt::Debug,
        simd::{Mask, Simd},
    };

    use rand::distr::{Distribution, StandardUniform};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    fn test_carry_add_per_type_lane_count<T, const N: usize>()
    where
        T: SimdElement + CarryingAdd<CarryT = bool> + PartialEq + Debug,
        Simd<T, N>: CarryingAdd<CarryT = Mask<<T as SimdElement>::Mask, N>>,
        StandardUniform: Distribution<Simd<T, N>> + Distribution<Mask<<T as SimdElement>::Mask, N>>,
    {
        let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0000_0001);

        let l: Simd<T, N> = StandardUniform.sample(&mut rng);
        let r: Simd<T, N> = StandardUniform.sample(&mut rng);
        let mask: Mask<<T as SimdElement>::Mask, N> = StandardUniform.sample(&mut rng);

        let l_arr = l.to_array();
        let r_arr = r.to_array();
        let mask_arr = mask.to_array();

        let (res, flag) = l.carrying_add(r, mask);
        let flag_arr = flag.to_array();
        for i in 0..N {
            assert_eq!(
                l_arr[i].carrying_add(r_arr[i], mask_arr[i]),
                (res[i], flag_arr[i]),
                "lane {i}: l={:?} r={:?} mask={}",
                l_arr[i],
                r_arr[i],
                mask_arr[i],
            );
        }
    }

    fn test_carry_add_per_type<T>()
    where
        T: SimdElement + CarryingAdd<CarryT = bool> + PartialEq + Debug,
        Simd<T, 1>: CarryingAdd<CarryT = Mask<<T as SimdElement>::Mask, 1>>,
        Simd<T, 2>: CarryingAdd<CarryT = Mask<<T as SimdElement>::Mask, 2>>,
        Simd<T, 4>: CarryingAdd<CarryT = Mask<<T as SimdElement>::Mask, 4>>,
        Simd<T, 8>: CarryingAdd<CarryT = Mask<<T as SimdElement>::Mask, 8>>,
        Simd<T, 16>: CarryingAdd<CarryT = Mask<<T as SimdElement>::Mask, 16>>,
        Simd<T, 32>: CarryingAdd<CarryT = Mask<<T as SimdElement>::Mask, 32>>,
        Simd<T, 64>: CarryingAdd<CarryT = Mask<<T as SimdElement>::Mask, 64>>,
        StandardUniform: Distribution<Simd<T, 1>>
            + Distribution<Simd<T, 2>>
            + Distribution<Simd<T, 4>>
            + Distribution<Simd<T, 8>>
            + Distribution<Simd<T, 16>>
            + Distribution<Simd<T, 32>>
            + Distribution<Simd<T, 64>>
            + Distribution<Mask<<T as SimdElement>::Mask, 1>>
            + Distribution<Mask<<T as SimdElement>::Mask, 2>>
            + Distribution<Mask<<T as SimdElement>::Mask, 4>>
            + Distribution<Mask<<T as SimdElement>::Mask, 8>>
            + Distribution<Mask<<T as SimdElement>::Mask, 16>>
            + Distribution<Mask<<T as SimdElement>::Mask, 32>>
            + Distribution<Mask<<T as SimdElement>::Mask, 64>>,
    {
        test_carry_add_per_type_lane_count::<T, 1>();
        test_carry_add_per_type_lane_count::<T, 2>();
        test_carry_add_per_type_lane_count::<T, 4>();
        test_carry_add_per_type_lane_count::<T, 8>();
        test_carry_add_per_type_lane_count::<T, 16>();
        test_carry_add_per_type_lane_count::<T, 32>();
        test_carry_add_per_type_lane_count::<T, 64>();
    }

    #[test]
    fn test_carry_add() {
        test_carry_add_per_type::<u8>();
        test_carry_add_per_type::<u16>();
        test_carry_add_per_type::<u32>();
        test_carry_add_per_type::<u64>();
    }
}
