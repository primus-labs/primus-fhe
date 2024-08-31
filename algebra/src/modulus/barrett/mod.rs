//! This module implements some functions and methods for
//! modular arithmetic based on barrett reduction.
//!
//! Barrett reduction computes `r ≡ x mod m` given `x` and `m`
//! and return `r` where `r < m`.
//!
//! First, we need decide the radix `b`, which is chosen to be close to
//! the word-size of the processor. Here, `b` = 2^64.
//!
//! The algorithm then precomputes a quantity ratio `µ = ⌊b^(2k)/m⌋`,
//! where `k` is the length of `m` based on radix `b`.
//!
//! For example, we denote `x` = (x_(2k-1) ... x_1 x_0)
//! and `m` = (m_(k-1) ... m_1 m_0) (m_(k-1) ≠ 0) based on radix `b`.
//!
//! Then, the algorithm will output `r ≡ x mod m` with the below procedures:
//!
//! 1. `q1 ← ⌊x/b^(k-1)⌋`, `q2 ← q1 · µ`, `q3 ← ⌊q2/b^(k+1)⌋`.
//! 2. `r1 ← x mod b^(k+1)`, `r2 ← (q3 · m) mod b^(k+1)`, `r ← r1 - r2`.
//! 3. If `r ≥ m` do: `r ← r - m`.
//! 4. Return(`r`).

#[macro_use]
mod internal_macros;
mod ops;

/// A modulus, using barrett reduction algorithm.
///
/// The struct stores the modulus number and some precomputed
/// data. Here, `b` = 2^T::BITS
///
/// It's efficient if many reductions are performed with a single modulus.
#[derive(Debug, Clone, Copy)]
pub struct BarrettModulus<T: Copy> {
    /// the value to indicate the modulus
    value: T,
    /// ratio `µ` = ⌊b^2/value⌋
    ratio: [T; 2],
}

impl<T: Copy> BarrettModulus<T> {
    /// Returns the value of this [`BarrettModulus<T>`].
    #[inline]
    pub const fn value(&self) -> T {
        self.value
    }

    /// Returns the ratio of this [`BarrettModulus<T>`].
    #[inline]
    pub const fn ratio(&self) -> [T; 2] {
        self.ratio
    }
}

impl_barrett_modulus!(impl BarrettModulus<u8>; WideType: u16);
impl_barrett_modulus!(impl BarrettModulus<u16>; WideType: u32);
impl_barrett_modulus!(impl BarrettModulus<u32>; WideType: u64);
impl_barrett_modulus!(impl BarrettModulus<u64>; WideType: u128);

#[cfg(test)]
mod tests {
    use rand::prelude::*;

    use crate::reduce::Reduce;

    use super::*;

    #[test]
    fn test_modulus_create() {
        let mut rng = thread_rng();

        let _m = BarrettModulus::<u8>::new(rng.gen_range(2..=(u8::MAX >> 2)));
        let _m = BarrettModulus::<u16>::new(rng.gen_range(2..=(u16::MAX >> 2)));
        let _m = BarrettModulus::<u32>::new(rng.gen_range(2..=(u32::MAX >> 2)));
        let _m = BarrettModulus::<u64>::new(rng.gen_range(2..=(u64::MAX >> 2)));
    }

    #[test]
    fn test_barret_reduce() {
        let mut rng = thread_rng();

        let m: u64 = rng.gen_range(2..=(u64::MAX >> 2));
        let modulus = BarrettModulus::<u64>::new(m);

        let v: u64 = rng.gen();
        assert_eq!(v.reduce(modulus), v % m);
    }

    #[test]
    fn test_barret_reduce_128() {
        let mut rng = thread_rng();

        let m: u64 = rng.gen_range(2..=(u64::MAX >> 2));
        let modulus = BarrettModulus::<u64>::new(m);

        let lw64: u64 = rng.gen();
        let hw64: u64 = rng.gen();
        let v: u128 = ((hw64 as u128) << 64) + (lw64 as u128);
        assert_eq!([lw64, hw64].reduce(modulus), (v % (m as u128)) as u64);
        assert_eq!((lw64, hw64).reduce(modulus), (v % (m as u128)) as u64);
    }

    #[test]
    fn test_barrett_const() {
        const MODULUS1: BarrettModulus<u32> = BarrettModulus::<u32>::new(17);
        const MODULUS2: BarrettModulus<u32> = BarrettModulus::<u32>::new(101);
        const MODULUS3: BarrettModulus<u64> = BarrettModulus::<u64>::new(521);

        const A: u32 = MODULUS1.bit_count();
        const B: u32 = MODULUS2.bit_count();
        const C: u32 = MODULUS3.bit_count();

        assert_eq!(MODULUS1.bit_count(), 5);
        assert_eq!(MODULUS2.bit_count(), 7);
        assert_eq!(MODULUS3.bit_count(), 10);

        assert_eq!(A, 5);
        assert_eq!(B, 7);
        assert_eq!(C, 10);
    }
}
