#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::constants::MODULUS_BIT_COUNT_MAX;

use super::{Modulo, ModuloAssign};

mod add;
// mod add_mul;
// mod dot_product;
// mod pow;
// mod inverse;
mod multiply;
mod neg;
mod sub;

/// A prime modulus, using barrett reduction algorithm.
///
/// The struct stores the modulus number and some precomputed
/// data. Here, the radix `b` = 2^64.
///
/// It's efficient if many reductions are performed with a single modulus.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrimeModulus {
    /// the u64 value to indicate the modulus
    value: u64,
    /// ratio `µ` = ⌊b^2/value⌋
    ratio: [u64; 2],
    /// the bit count of the value
    bit_count: u32,
}

impl PrimeModulus {
    pub const fn new(value: u64) -> Self {
        match value {
            0 | 1 => panic!("modulus can't be 0 or 1."),
            _ => {
                let bit_count = 64 - value.leading_zeros();
                assert!(bit_count <= MODULUS_BIT_COUNT_MAX as u32);

                let (numerator, _) = div_inplace(value);

                Self {
                    value,
                    ratio: [numerator[0], numerator[1]],
                    bit_count,
                }
            }
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn ratio(&self) -> [u64; 2] {
        self.ratio
    }

    pub fn bit_count(&self) -> u32 {
        self.bit_count
    }
}

const BITS: u8 = 64;
const HALF_BITS: u8 = BITS / 2;
const HALF: u64 = (1 << HALF_BITS) - 1;

#[inline]
const fn div_rem(numerator: u64, divisor: u64) -> (u64, u64) {
    (numerator / divisor, numerator % divisor)
}

/// Divide a two u64 numerator by a one u64 divisor, returns quotient and remainder:
///
/// Note: the caller must ensure that both the quotient and remainder will fit into a single u64.
/// This is _not_ true for an arbitrary numerator/denominator.
///
/// (This function also matches what the x86 divide instruction does).
#[inline]
const fn div_wide(hi: u64, lo: u64, divisor: u64) -> (u64, u64) {
    debug_assert!(hi < divisor);

    let lhs = lo as u128 | ((hi as u128) << BITS);
    let rhs = divisor as u128;
    ((lhs / rhs) as u64, (lhs % rhs) as u64)
}

/// For small divisors, we can divide without promoting to `u128` by
/// using half-size pieces of u64, like long-division.
#[inline]
const fn div_half(rem: u64, digit: u64, divisor: u64) -> (u64, u64) {
    debug_assert!(rem < divisor && divisor <= HALF);
    let (hi, rem) = div_rem((rem << HALF_BITS) | (digit >> HALF_BITS), divisor);
    let (lo, rem) = div_rem((rem << HALF_BITS) | (digit & HALF), divisor);
    ((hi << HALF_BITS) | lo, rem)
}

const fn div_inplace(value: u64) -> ([u64; 3], u64) {
    assert!(value != 0);

    let mut numerator = [0, 0, 0];
    let mut rem = 0;

    if value <= HALF {
        let (q, r) = div_half(rem, 1, value);
        numerator[2] = q;
        rem = r;

        let (q, r) = div_half(rem, 0, value);
        numerator[1] = q;
        rem = r;

        let (q, r) = div_half(rem, 0, value);
        numerator[0] = q;
        rem = r;
    } else {
        let (q, r) = div_wide(rem, 1, value);
        numerator[2] = q;
        rem = r;

        let (q, r) = div_wide(rem, 0, value);
        numerator[1] = q;
        rem = r;

        let (q, r) = div_wide(rem, 0, value);
        numerator[0] = q;
        rem = r;
    }
    (numerator, rem)
}

impl Modulo<PrimeModulus> for u64 {
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
    fn modulo(self, modulus: PrimeModulus) -> Self::Output {
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

impl Modulo<PrimeModulus> for [u64; 2] {
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
    fn modulo(self, modulus: PrimeModulus) -> Self::Output {
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

impl Modulo<PrimeModulus> for (u64, u64) {
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
    fn modulo(self, modulus: PrimeModulus) -> Self::Output {
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

impl Modulo<PrimeModulus> for &[u64] {
    type Output = u64;

    /// Caculates `self (mod modulus)` when value's length > 0.
    fn modulo(self, modulus: PrimeModulus) -> Self::Output {
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

impl ModuloAssign<PrimeModulus> for u64 {
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
    fn modulo_assign(&mut self, modulus: PrimeModulus) {
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
