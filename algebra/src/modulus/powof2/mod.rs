use crate::{
    integer::UnsignedInteger,
    reduce::{Modulus, ModulusValue},
};

#[macro_use]
mod macros;
mod ops;

/// A struct for power of 2 modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PowOf2Modulus<T: UnsignedInteger> {
    /// The special value for performing `reduce`.
    ///
    /// It's equal to modulus value sub one.
    mask: T,
}

impl<T: UnsignedInteger> PowOf2Modulus<T> {
    /// Returns the value of this [`PowOf2Modulus<T>`].
    #[inline]
    pub fn value(&self) -> T {
        self.mask + T::ONE
    }

    /// Returns the mask of this [`PowOf2Modulus<T>`],
    /// which is equal to modulus value sub one.
    #[inline]
    pub const fn mask(&self) -> T {
        self.mask
    }
}

impl<T: UnsignedInteger> Modulus<T> for PowOf2Modulus<T> {
    #[inline]
    fn from_value(value: ModulusValue<T>) -> Self {
        match value {
            ModulusValue::PowerOf2(value) => Self {
                mask: value - T::ONE,
            },
            _ => panic!("The value is not a power of 2."),
        }
    }

    #[inline]
    fn modulus_value(&self) -> ModulusValue<T> {
        ModulusValue::PowerOf2(self.value())
    }

    #[inline]
    fn modulus_minus_one(&self) -> T {
        self.mask
    }
}

impl_powof2_modulus!(impl PowOf2Modulus<u8>);
impl_powof2_modulus!(impl PowOf2Modulus<u16>);
impl_powof2_modulus!(impl PowOf2Modulus<u32>);
impl_powof2_modulus!(impl PowOf2Modulus<u64>);
impl_powof2_modulus!(impl PowOf2Modulus<usize>);
impl_powof2_modulus!(impl PowOf2Modulus<u128>);

#[cfg(test)]
mod tests {
    use rand::{distributions::Uniform, prelude::*};

    use crate::reduce::*;

    use super::*;

    #[test]
    fn test_modulus_create() {
        let mut rng = thread_rng();

        let _m = <PowOf2Modulus<u8>>::new(rng.gen_range(2..=(u8::MAX >> 2)).next_power_of_two());
        let _m = <PowOf2Modulus<u16>>::new(rng.gen_range(2..=(u16::MAX >> 2)).next_power_of_two());
        let _m = <PowOf2Modulus<u32>>::new(rng.gen_range(2..=(u32::MAX >> 2)).next_power_of_two());
        let _m = <PowOf2Modulus<u64>>::new(rng.gen_range(2..=(u64::MAX >> 2)).next_power_of_two());
        let _m =
            <PowOf2Modulus<u128>>::new(rng.gen_range(2..=(u128::MAX >> 2)).next_power_of_two());

        let _m = <PowOf2Modulus<u8>>::new_with_mask(
            rng.gen_range(2..=(u8::MAX >> 2)).next_power_of_two() - 1,
        );
        let _m = <PowOf2Modulus<u16>>::new_with_mask(
            rng.gen_range(2..=(u16::MAX >> 2)).next_power_of_two() - 1,
        );
        let _m = <PowOf2Modulus<u32>>::new_with_mask(
            rng.gen_range(2..=(u32::MAX >> 2)).next_power_of_two() - 1,
        );
        let _m = <PowOf2Modulus<u64>>::new_with_mask(
            rng.gen_range(2..=(u64::MAX >> 2)).next_power_of_two() - 1,
        );
        let _m = <PowOf2Modulus<u128>>::new_with_mask(
            rng.gen_range(2..=(u128::MAX >> 2)).next_power_of_two() - 1,
        );
    }

    #[test]
    #[should_panic]
    fn test_modulus_create_panic() {
        let mut rng = thread_rng();

        let m = loop {
            let r = rng.gen_range(0..=(u64::MAX >> 2));
            if !r.is_power_of_two() {
                break r;
            }
        };

        let _m = PowOf2Modulus::<u64>::new(m);
    }

    #[test]
    fn test_reduce() {
        let mut rng = thread_rng();

        let m: u64 = rng.gen_range(2..=(u64::MAX >> 2)).next_power_of_two();
        let modulus = PowOf2Modulus::<u64>::new(m);
        let dis = Uniform::new_inclusive(0, modulus.mask());

        let v: u64 = rng.sample(dis);
        assert_eq!(modulus.reduce(v), v % m);

        let a: u64 = rng.sample(dis);
        let b: u64 = rng.sample(dis);
        assert_eq!(modulus.reduce_add(a, b), (a + b) % m);

        let a: u64 = rng.sample(dis);
        let b: u64 = rng.sample(dis);
        assert_eq!(modulus.reduce_sub(a, b), (m + a - b) % m);

        let a: u64 = rng.sample(dis);
        let b: u64 = rng.sample(dis);
        assert_eq!(
            modulus.reduce_mul(a, b),
            ((a as u128 * b as u128) % m as u128) as u64
        );

        let a: u64 = rng.sample(dis);
        let a_neg = modulus.reduce_neg(a);
        assert_eq!(modulus.reduce_add(a, a_neg), 0);

        assert_eq!(modulus.reduce_neg(0), 0);
    }
}
