//! This module implements some functions and methods for
//! modular arithmetic based on barrett reduction.
//!
//! Barrett reduction computes `r ≡ x mod m` given `x` and `m`
//! and return `r`.
//!
//! Fisrt, we need decide the radix `b`, which is chosen to be close to
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
//! 1. `q1 ← ⌊x/b^(k−1)⌋`, `q2 ← q1 · µ`, `q3 ← ⌊q2/b^(k+1)⌋`.
//! 2. `r1 ← x mod b^(k+1)`, `r2 ← (q3 · m) mod b^(k+1)`, `r ← r1 − r2`.
//! 3. If `r ≥ m` do: `r ← r − m`.
//! 4. Return(`r`).

use crate::modulo::{MulModulo, MulModuloAssign};
use crate::primitive::Widening;

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

/// A number used for fast modular multiplication.
///
/// This is efficient if many operations are multiplied by
/// the same number and then reduced with the same modulus.
#[derive(Clone, Copy, Default)]
pub struct MulModuloFactor<T> {
    /// value
    pub value: T,

    /// quotient
    pub quotient: T,
}

impl<T: Copy> MulModuloFactor<T> {
    /// Returns the value of this [`MulModuloFactor`].
    #[inline]
    pub fn value(&self) -> T {
        self.value
    }

    /// Returns the quotient of this [`MulModuloFactor`].
    #[inline]
    pub fn quotient(&self) -> T {
        self.quotient
    }
}

impl_mul_modulo_factor!(impl MulModuloFactor<u8>; WideType: u16);
impl_mul_modulo_factor!(impl MulModuloFactor<u16>; WideType: u32);
impl_mul_modulo_factor!(impl MulModuloFactor<u32>; WideType: u64);
impl_mul_modulo_factor!(impl MulModuloFactor<u64>; WideType: u128);

impl_mul_modulo_factor_ops!(impl MulModuloFactor<u8>);
impl_mul_modulo_factor_ops!(impl MulModuloFactor<u16>);
impl_mul_modulo_factor_ops!(impl MulModuloFactor<u32>);
impl_mul_modulo_factor_ops!(impl MulModuloFactor<u64>);

#[cfg(test)]
mod tests {
    use rand::{prelude::*, thread_rng};

    use crate::modulo::Modulo;

    use super::*;

    const ROUND: i32 = 5;

    #[test]
    fn test_modulus_create() {
        let mut rng = thread_rng();
        for _ in 0..ROUND {
            let _m = Modulus::<u8>::new(rng.gen_range(2..=(u8::MAX >> 2)));
            let _m = Modulus::<u16>::new(rng.gen_range(2..=(u16::MAX >> 2)));
            let _m = Modulus::<u32>::new(rng.gen_range(2..=(u32::MAX >> 2)));
            let _m = Modulus::<u64>::new(rng.gen_range(2..=(u64::MAX >> 2)));
        }
    }

    #[test]
    fn test_barret_reduce() {
        let mut rng = thread_rng();
        for _ in 0..ROUND {
            let m: u64 = rng.gen_range(2..=(u64::MAX >> 2));
            let modulus = Modulus::<u64>::new(m);
            for _ in 0..ROUND {
                let v: u64 = rng.gen();
                assert_eq!(v.modulo(&modulus), v % m);
            }
        }
    }

    #[test]
    fn test_barret_reduce_128() {
        let mut rng = thread_rng();
        for _ in 0..ROUND {
            let m: u64 = rng.gen_range(2..=(u64::MAX >> 2));
            let modulus = Modulus::<u64>::new(m);
            for _ in 0..ROUND {
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
        for _ in 0..ROUND {
            let m: u64 = r.gen_range(2..=(u64::MAX >> 2));
            let modulus = Modulus::<u64>::new(m);
            for _ in 0..ROUND {
                let lw64: u64 = r.gen();
                let hw64: u64 = r.gen();
                let v: u128 = ((hw64 as u128) << 64) + (lw64 as u128);
                assert_eq!((lw64, hw64).modulo(&modulus), (v % (m as u128)) as u64);
            }
        }
    }
}
