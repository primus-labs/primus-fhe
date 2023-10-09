use std::hash::Hash;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    constants::MODULUS_BIT_COUNT_MAX, number_theory::probably_prime, slice::slice_div_value_inplace,
};

use super::{Modulo, ModuloAssign};

mod add;
// mod add_mul;
// mod dot_product;
mod pow;
// mod inverse;
mod multiply;
mod neg;
mod sub;

/// A modulus, using barrett reduction algorithm.
///
/// The struct stores the modulus number and some precomputed
/// data. Here, the radix `b` = 2^64.
///
/// It's efficient if many reductions are performed with a single modulus.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Modulus {
    /// the u64 value to indicate the modulus
    value: u64,
    /// ratio `µ` = ⌊b^2/value⌋
    ratio: [u64; 2],
    /// the bit count of the value
    bit_count: u32,
    /// show whether the value is prime
    is_prime: bool,
}

impl Modulus {
    /// Creates a [`Modulus`] instance.
    ///
    /// - `value`: The value of the modulus.
    ///
    /// # Panics
    ///
    /// The `value`'s `bit_count` should be at least
    /// [`MODULUS_BIT_COUNT_MIN`](crate::constants::MODULUS_BIT_COUNT_MIN)
    /// and at most [`MODULUS_BIT_COUNT_MAX`], others will panic.
    pub fn new(value: u64) -> Self {
        match value {
            0 | 1 => panic!("modulus can't be 0 or 1."),
            _ => {
                let bit_count = 64 - value.leading_zeros();
                assert!(bit_count <= MODULUS_BIT_COUNT_MAX as u32);

                let mut numerator = [0, 0, 1];
                slice_div_value_inplace(&mut numerator, value);

                let mut modulus = Self {
                    value,
                    ratio: [numerator[0], numerator[1]],
                    bit_count,
                    is_prime: false,
                };

                modulus.is_prime = probably_prime(&modulus, 60);
                modulus
            }
        }
    }

    /// Get the `value` of the current [`Modulus`].
    #[inline]
    pub fn value(&self) -> u64 {
        self.value
    }

    // /// Check whether the `value` of the current [`Modulus`] equals 0.
    // #[inline]
    // pub fn is_zero(&self) -> bool {
    //     self.value == 0
    // }

    /// Get the `ratio` of the current [`Modulus`].
    #[inline]
    pub fn ratio(&self) -> [u64; 2] {
        self.ratio
    }

    /// Get the `bit_count` of the current [`Modulus`].
    #[inline]
    pub fn bit_count(&self) -> u32 {
        self.bit_count
    }

    /// Check whether the `value` of the current [`Modulus`] is prime.
    #[inline]
    pub fn is_prime(&self) -> bool {
        self.is_prime
    }

    /// Caculates `value (mod self)`.
    #[inline]
    pub fn reduce(&self, value: u64) -> u64 {
        value.modulo(self)
    }
}

impl Hash for Modulus {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl PartialEq for Modulus {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for Modulus {}

impl PartialOrd for Modulus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl Ord for Modulus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl Modulo<&Modulus> for u64 {
    type Output = Self;

    /// Caculates `self (mod modulus)`.
    ///
    /// ## Procedure
    ///
    /// We denote `x` = `self`  and `m` = `modulus` here.
    ///
    /// The algorithm will output `r` = `x` mod `m` with the below procedures:
    ///
    /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
    /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` − `r2`.
    /// 3. If `r` ≥ `m` do: `r` ← `r` − `m`.
    /// 4. Return(`r`).
    ///
    /// ## Proof:
    ///
    /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
    ///
    /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
    ///
    /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
    ///
    /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
    ///
    /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
    fn modulo(self, modulus: &Modulus) -> Self::Output {
        let ratio = modulus.ratio();

        // Step 1.
        //              ratio[1]  ratio[0]
        //         *                self
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //            +-------------------+
        //            |  tmp1   |         |    <-- self * ratio[0]
        //            +-------------------+
        //   +------------------+
        //   |      tmp2        |              <-- self * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //   +--------+
        //   |   q3   |
        //   +--------+
        let tmp = (self as u128 * ratio[0] as u128) >> 64; // tmp1
        let tmp = ((self as u128 * ratio[1] as u128 + tmp) >> 64) as u64; // q3

        // Step 2.
        let tmp = self.wrapping_sub(tmp.wrapping_mul(modulus.value())); // r = r1 -r2

        // Step 3. and 4.
        if tmp >= modulus.value() {
            tmp - modulus.value()
        } else {
            tmp
        }
    }
}

impl Modulo<&Modulus> for [u64; 2] {
    type Output = u64;

    /// Caculates `self (mod modulus)`.
    ///
    /// ## Procedure
    ///
    /// We denote `x` = `self`  and `m` = `modulus` here.
    ///
    /// The algorithm will output `r` = `x` mod `m` with the below procedures:
    ///
    /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
    /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` − `r2`.
    /// 3. If `r` ≥ `m` do: `r` ← `r` − `m`.
    /// 4. Return(`r`).
    ///
    /// ## Proof:
    ///
    /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
    ///
    /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
    ///
    /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
    ///
    /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
    ///
    /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
    fn modulo(self, modulus: &Modulus) -> Self::Output {
        let ratio = modulus.ratio();

        // Step 1.
        //                        ratio[1]  ratio[0]
        //                   *    value[1]  value[0]
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //                      +-------------------+
        //                      |         a         |    <-- value[0] * ratio[0]
        //                      +-------------------+
        //             +------------------+
        //             |        b         |              <-- value[0] * ratio[1]
        //             +------------------+
        //             +------------------+
        //             |        c         |              <-- value[1] * ratio[0]
        //             +------------------+
        //   +------------------+
        //   |        d         |                        <-- value[1] * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //   +------------------+
        //   |        q3        |
        //   +------------------+
        let a = ratio[0] as u128 * self[0] as u128;
        let b_plus_a_left = ratio[1] as u128 * self[0] as u128 + (a >> 64);

        let c = ratio[0] as u128 * self[1] as u128;
        let d = ratio[1] as u128 * self[1] as u128;

        let tmp = d.wrapping_add((b_plus_a_left + c) >> 64) as u64;

        // Step 2.
        let r = self[0].wrapping_sub(tmp.wrapping_mul(modulus.value()));

        // Step 3. and 4.
        if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        }
    }
}

impl Modulo<&Modulus> for (u64, u64) {
    type Output = u64;

    /// Caculates `self (mod modulus)`.
    ///
    /// ## Procedure
    ///
    /// We denote `x` = `self`  and `m` = `modulus` here.
    ///
    /// The algorithm will output `r` = `x` mod `m` with the below procedures:
    ///
    /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
    /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` − `r2`.
    /// 3. If `r` ≥ `m` do: `r` ← `r` − `m`.
    /// 4. Return(`r`).
    ///
    /// ## Proof:
    ///
    /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
    ///
    /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
    ///
    /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
    ///
    /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
    ///
    /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
    fn modulo(self, modulus: &Modulus) -> Self::Output {
        let ratio = modulus.ratio();

        // Step 1.
        //                        ratio[1]  ratio[0]
        //                   *    value.1   value.0
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //                      +-------------------+
        //                      |         a         |    <-- value.0 * ratio[0]
        //                      +-------------------+
        //             +------------------+
        //             |        b         |              <-- value.0 * ratio[1]
        //             +------------------+
        //             +------------------+
        //             |        c         |              <-- value.1 * ratio[0]
        //             +------------------+
        //   +------------------+
        //   |        d         |                        <-- value.1 * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //   +------------------+
        //   |        q3        |
        //   +------------------+
        let a = ratio[0] as u128 * self.0 as u128;
        let b_plus_a_left = ratio[1] as u128 * self.0 as u128 + (a >> 64);

        let c = ratio[0] as u128 * self.1 as u128;
        let d = ratio[1] as u128 * self.1 as u128;

        let tmp = d.wrapping_add((b_plus_a_left + c) >> 64) as u64;

        // Step 2.
        let r = self.0.wrapping_sub(tmp.wrapping_mul(modulus.value()));

        // Step 3. and 4.
        if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        }
    }
}

impl Modulo<&Modulus> for &[u64] {
    type Output = u64;

    /// Caculates `self (mod modulus)` when value's length > 0.
    fn modulo(self, modulus: &Modulus) -> Self::Output {
        match self {
            &[] => unreachable!(),
            &[v] => {
                if v < modulus.value() {
                    v
                } else {
                    v.modulo(modulus)
                }
            }
            [other @ .., last] => other
                .iter()
                .rfold(*last, |acc, x| [*x, acc].modulo(modulus)),
        }
    }
}

impl ModuloAssign<&Modulus> for u64 {
    /// Caculates `self (mod modulus)`.
    ///
    /// ## Procedure
    ///
    /// We denote `x` = `self`  and `m` = `modulus` here.
    ///
    /// The algorithm will output `r` = `x` mod `m` with the below procedures:
    ///
    /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
    /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` − `r2`.
    /// 3. If `r` ≥ `m` do: `r` ← `r` − `m`.
    /// 4. Return(`r`).
    ///
    /// ## Proof:
    ///
    /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
    ///
    /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
    ///
    /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
    ///
    /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
    ///
    /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
    fn modulo_assign(&mut self, modulus: &Modulus) {
        let ratio = modulus.ratio();

        // Step 1.
        //              ratio[1]  ratio[0]
        //         *                self
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //            +-------------------+
        //            |  tmp1   |         |    <-- self * ratio[0]
        //            +-------------------+
        //   +------------------+
        //   |      tmp2        |              <-- self * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //   +--------+
        //   |   q3   |
        //   +--------+
        let tmp = (*self as u128 * ratio[0] as u128) >> 64; // tmp1
        let tmp = ((*self as u128 * ratio[1] as u128 + tmp) >> 64) as u64; // q3

        // Step 2.
        *self = self.wrapping_sub(tmp.wrapping_mul(modulus.value())); // r = r1 -r2

        // Step 3. and 4.
        if *self >= modulus.value() {
            *self -= modulus.value();
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use rand::{prelude::*, thread_rng};

//     use super::*;

//     #[test]
//     fn test_modulus_create() {
//         let mut rng = thread_rng();
//         for _ in 0..10 {
//             let _m = Modulus::new(rng.gen_range(2..=(u64::MAX >> 2)));
//         }
//     }

//     #[test]
//     fn test_barret_reduce() {
//         let mut rng = thread_rng();
//         for _ in 0..10 {
//             let m: u64 = rng.gen_range(2..=(u64::MAX >> 2));
//             let modulus = Modulus::new(m);
//             for _ in 0..10 {
//                 let v: u64 = rng.gen();
//                 assert_eq!(v.modulo(&modulus), v % m);
//             }
//         }
//     }

//     #[test]
//     fn test_barret_reduce_128() {
//         let mut rng = thread_rng();
//         for _ in 0..10 {
//             let m: u64 = rng.gen_range(2..=(u64::MAX >> 2));
//             let modulus = Modulus::new(m);
//             for _ in 0..10 {
//                 let lw64: u64 = rng.gen();
//                 let hw64: u64 = rng.gen();
//                 let v: u128 = ((hw64 as u128) << 64) + (lw64 as u128);
//                 assert_eq!([lw64, hw64].modulo(&modulus), (v % (m as u128)) as u64);
//             }
//         }
//     }

//     #[test]
//     fn test_barret_reduce_128_tuple() {
//         let mut r = thread_rng();
//         for _ in 0..10 {
//             let m: u64 = r.gen_range(2..=(u64::MAX >> 2));
//             let modulus = Modulus::new(m);
//             for _ in 0..10 {
//                 let lw64: u64 = r.gen();
//                 let hw64: u64 = r.gen();
//                 let v: u128 = ((hw64 as u128) << 64) + (lw64 as u128);
//                 assert_eq!((lw64, hw64).modulo(&modulus), (v % (m as u128)) as u64);
//             }
//         }
//     }

//     #[test]
//     fn test_barret_reduce_slice() {
//         let mut r = thread_rng();
//         for _ in 0..10 {
//             let value: u64 = r.gen_range(2..=(u64::MAX >> 2));
//             let modulus = Modulus::new(value);
//             for _ in 0..10 {
//                 let mut x: [u64; 4] = [r.gen(), r.gen(), r.gen(), r.gen()];
//                 let rem = x.modulo(&modulus);
//                 assert_eq!(rem, slice_div_value_inplace(&mut x, value));
//             }
//         }
//     }
// }
