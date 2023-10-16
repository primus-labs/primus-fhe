#[macro_use]
mod internal_macros;

mod ops;

/// A prime modulus, using barrett reduction algorithm.
///
/// The struct stores the modulus number and some precomputed
/// data. Here, `b` = 2^T::BITS
///
/// It's efficient if many reductions are performed with a single modulus.
#[derive(Clone)]
pub struct Modulus<T> {
    /// the value to indicate the modulus
    value: T,
    /// ratio `µ` = ⌊b^2/value⌋
    ratio: [T; 2],
    /// the bit count of the value
    bit_count: u32,
}

impl<T: Copy> Modulus<T> {
    /// Returns the value of this [`Modulus<T>`].
    #[inline]
    pub fn value(&self) -> T {
        self.value
    }

    /// Returns the ratio of this [`Modulus<T>`].
    #[inline]
    pub fn ratio(&self) -> [T; 2] {
        self.ratio
    }
}

impl<T> Modulus<T> {
    /// Returns the bit count of this [`Modulus<T>`].
    #[inline]
    pub fn bit_count(&self) -> u32 {
        self.bit_count
    }
}

impl_prime_modulus!(impl Modulus<u8>; WideType: u16);
impl_prime_modulus!(impl Modulus<u16>; WideType: u32);
impl_prime_modulus!(impl Modulus<u32>; WideType: u64);
impl_prime_modulus!(impl Modulus<u64>; WideType: u128);

#[cfg(test)]
mod tests {
    use rand::{prelude::*, thread_rng};

    use crate::modulo::Modulo;

    use super::*;

    #[test]
    fn test_modulus_create() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let _m = Modulus::<u8>::new(rng.gen_range(2..=(u8::MAX >> 1)));
            let _m = Modulus::<u16>::new(rng.gen_range(2..=(u16::MAX >> 1)));
            let _m = Modulus::<u32>::new(rng.gen_range(2..=(u32::MAX >> 1)));
            let _m = Modulus::<u64>::new(rng.gen_range(2..=(u64::MAX >> 1)));
        }
    }

    #[test]
    fn test_barret_reduce() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let m: u64 = rng.gen_range(2..=(u64::MAX >> 1));
            let modulus = Modulus::<u64>::new(m);
            for _ in 0..10 {
                let v: u64 = rng.gen();
                assert_eq!(v.modulo(&modulus), v % m);
            }
        }
    }

    #[test]
    fn test_barret_reduce_128() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let m: u64 = rng.gen_range(2..=(u64::MAX >> 1));
            let modulus = Modulus::<u64>::new(m);
            for _ in 0..10 {
                let lw64: u64 = rng.gen();
                let hw64: u64 = rng.gen();
                let v: u128 = ((hw64 as u128) << 64) + (lw64 as u128);
                assert_eq!([lw64, hw64].modulo(&modulus), (v % (m as u128)) as u64);
            }
        }
    }

    #[test]
    fn test_barret_reduce_128_tuple() {
        let mut r = thread_rng();
        for _ in 0..10 {
            let m: u64 = r.gen_range(2..=(u64::MAX >> 1));
            let modulus = Modulus::<u64>::new(m);
            for _ in 0..10 {
                let lw64: u64 = r.gen();
                let hw64: u64 = r.gen();
                let v: u128 = ((hw64 as u128) << 64) + (lw64 as u128);
                assert_eq!((lw64, hw64).modulo(&modulus), (v % (m as u128)) as u64);
            }
        }
    }

    // #[test]
    // fn test_barret_reduce_slice() {
    //     let mut r = thread_rng();
    //     for _ in 0..10 {
    //         let value: u64 = r.gen_range(2..=(u64::MAX >> 2));
    //         let modulus = Modulus::<u64>::new(value);
    //         for _ in 0..10 {
    //             let mut x: [u64; 4] = [r.gen(), r.gen(), r.gen(), r.gen()];
    //             let rem = x.modulo(&modulus);
    //             assert_eq!(rem, slice_div_value_inplace(&mut x, value));
    //         }
    //     }
    // }
}
