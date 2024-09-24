use std::ops::Add;

use num_traits::ConstOne;

#[macro_use]
mod internal_macros;

/// A struct for power of 2 modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PowOf2Modulus<T: Copy> {
    /// The special value for performing `reduce`.
    ///
    /// It's equal to modulus value sub one.
    mask: T,
}

impl<T: Copy> PowOf2Modulus<T> {
    /// Returns the mask of this [`PowOf2Modulus<T>`],
    /// which is equal to modulus value sub one.
    #[inline]
    pub const fn mask(self) -> T {
        self.mask
    }
}

impl<T: Copy + ConstOne + Add<Output = T>> PowOf2Modulus<T> {
    /// Returns the value of this [`PowOf2Modulus<T>`].
    #[inline]
    pub fn value(self) -> T {
        self.mask + T::ONE
    }
}

impl_powof2_modulus!(impl PowOf2Modulus<u8>);
impl_powof2_modulus!(impl PowOf2Modulus<u16>);
impl_powof2_modulus!(impl PowOf2Modulus<u32>);
impl_powof2_modulus!(impl PowOf2Modulus<u64>);
impl_powof2_modulus!(impl PowOf2Modulus<u128>);

#[cfg(test)]
mod tests {
    use rand::prelude::*;
    use rand_distr::Uniform;

    use crate::reduce::*;

    use super::*;

    #[test]
    fn test_modulus_create() {
        let mut rng = thread_rng();

        let _m = PowOf2Modulus::<u8>::new(rng.gen_range(2..=(u8::MAX >> 2)).next_power_of_two());
        let _m = PowOf2Modulus::<u16>::new(rng.gen_range(2..=(u16::MAX >> 2)).next_power_of_two());
        let _m = PowOf2Modulus::<u32>::new(rng.gen_range(2..=(u32::MAX >> 2)).next_power_of_two());
        let _m = PowOf2Modulus::<u64>::new(rng.gen_range(2..=(u64::MAX >> 2)).next_power_of_two());
    }

    #[test]
    #[should_panic]
    fn test_modulus_create_panic() {
        let mut rng = thread_rng();
        let m;
        loop {
            let r = rng.gen_range(0..=(u64::MAX >> 2));
            if !r.is_power_of_two() {
                m = r;
                break;
            }
        }

        let _m = PowOf2Modulus::<u64>::new(m);
    }

    #[test]
    fn test_reduce() {
        let mut rng = thread_rng();

        let m: u64 = rng.gen_range(2..=(u64::MAX >> 2)).next_power_of_two();
        let modulus = PowOf2Modulus::<u64>::new(m);
        let dis = Uniform::new_inclusive(0, modulus.mask());

        let v: u64 = rng.sample(dis);
        assert_eq!(v.reduce(modulus), v % m);

        let a: u64 = rng.sample(dis);
        let b: u64 = rng.sample(dis);
        assert_eq!(a.add_reduce(b, modulus), (a + b) % m);

        let a: u64 = rng.sample(dis);
        let b: u64 = rng.sample(dis);
        assert_eq!(a.sub_reduce(b, modulus), (m + a - b) % m);

        let a: u64 = rng.sample(dis);
        let b: u64 = rng.sample(dis);
        assert_eq!(
            a.mul_reduce(b, modulus),
            ((a as u128 * b as u128) % m as u128) as u64
        );

        let a: u64 = rng.sample(dis);
        let a_neg = a.neg_reduce(modulus);
        assert_eq!(a_neg.add_reduce(a, modulus), 0);

        assert_eq!(0.neg_reduce(modulus), 0);
    }
}
