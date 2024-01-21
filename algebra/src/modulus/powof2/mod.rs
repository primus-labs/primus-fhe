#[macro_use]
mod internal_macros;
mod ops;

/// A struct for pow of 2 modulus.
#[derive(Clone, Copy)]
pub struct PowOf2Modulus<T: Copy> {
    /// the special value for performing `reduce`.
    mask: T,
}

impl<T: Copy> PowOf2Modulus<T> {
    /// Returns the mask of this [`PowOf2Modulus<T>`].
    #[inline]
    pub const fn mask(&self) -> T {
        self.mask
    }
}

impl_powof2_modulus!(impl PowOf2Modulus<u8>);
impl_powof2_modulus!(impl PowOf2Modulus<u16>);
impl_powof2_modulus!(impl PowOf2Modulus<u32>);
impl_powof2_modulus!(impl PowOf2Modulus<u64>);
impl_powof2_modulus!(impl PowOf2Modulus<u128>);

#[cfg(test)]
mod tests {
    use rand::{prelude::*, thread_rng};

    use crate::reduce::Reduce;

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
    fn test_barret_reduce() {
        let mut rng = thread_rng();

        let m: u64 = rng.gen_range(2..=(u64::MAX >> 2)).next_power_of_two();
        let modulus = PowOf2Modulus::<u64>::new(m);

        let v: u64 = rng.gen();
        assert_eq!(v.reduce(modulus), v % m);
    }
}