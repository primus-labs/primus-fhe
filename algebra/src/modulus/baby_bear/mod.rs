//! impl baby bear prime modulus
//!
//! This is derived from the [Plonky3](https://github.com/Plonky3/Plonky3/tree/main/baby-bear).

use crate::reduce::{ExpPowOf2Reduce, MulReduce};

mod ops;

/// The Baby Bear prime
/// This is the unique 31-bit prime with the highest possible 2 adicity (27).
pub const P: u32 = 0x78000001;
const MONTY_BITS: u32 = 32;
// We are defining MU = P^-1 (mod 2^MONTY_BITS). This is different from the usual convention
// (MU = -P^-1 (mod 2^MONTY_BITS)) but it avoids a carry.
const MONTY_MU: u32 = 0x88000001;

// This is derived from above.
// const MONTY_MASK: u32 = ((1u64 << MONTY_BITS) - 1) as u32;
const MONTY_MASK: u32 = u32::MAX;

/// The prime field `2^31 - 2^27 + 1`, a.k.a. the Baby Bear field.
#[derive(Clone, Copy)]
pub struct BabyBearModulus;

/// `0` in monty mode
pub const MONTY_ZERO: u32 = to_monty(0);
/// `1` in monty mode
pub const MONTY_ONE: u32 = to_monty(1);
/// `2` in monty mode
pub const MONTY_TWO: u32 = to_monty(2);
/// `-1` in monty mode
pub const MONTY_NEG_ONE: u32 = to_monty(P - 1);

fn try_inverse(value: u32) -> Option<u32> {
    if value == 0 {
        return None;
    }

    // From Fermat's little theorem, in a prime field `F_p`, the inverse of `a` is `a^(p-2)`.
    // Here p-2 = 2013265919 = 1110111111111111111111111111111_2.
    // Uses 30 Squares + 7 Multiplications => 37 Operations total.

    let p1 = value;

    let p100000000 = exp::<8>(p1);
    let p100000001 = mul(p100000000, p1);
    let p10000000000000000 = exp::<8>(p100000000);
    let p10000000100000001 = mul(p10000000000000000, p100000001);
    let p10000000100000001000 = exp::<3>(p10000000100000001);
    let p1000000010000000100000000 = exp::<5>(p10000000100000001000);
    let p1000000010000000100000001 = mul(p1000000010000000100000000, p1);
    let p1000010010000100100001001 = mul(p1000000010000000100000001, p10000000100000001000);
    let p10000000100000001000000010 = square(p1000000010000000100000001);
    let p11000010110000101100001011 = mul(p10000000100000001000000010, p1000010010000100100001001);
    let p100000001000000010000000100 = square(p10000000100000001000000010);
    let p111000011110000111100001111 =
        mul(p100000001000000010000000100, p11000010110000101100001011);
    let p1110000111100001111000011110000 = exp::<4>(p111000011110000111100001111);
    let p1110111111111111111111111111111 = mul(
        p1110000111100001111000011110000,
        p111000011110000111100001111,
    );

    Some(p1110111111111111111111111111111)
}

/// Convert a `u32` value into monty mode.
#[inline]
#[must_use]
pub const fn to_monty(x: u32) -> u32 {
    (((x as u64) << MONTY_BITS) % P as u64) as u32
}

/// Convert a constant u32 array into a constant Babybear monty array.
/// Saves every element in Monty Form
#[inline]
#[must_use]
#[allow(unused)]
const fn to_monty_array<const N: usize>(input: [u32; N]) -> [u32; N] {
    let mut output = [0; N];
    let mut i = 0;
    loop {
        if i == N {
            break;
        }
        output[i] = to_monty(input[i]);
        i += 1;
    }
    output
}

#[inline]
#[must_use]
#[allow(unused)]
const fn to_monty_64(x: u64) -> u32 {
    (((x as u128) << MONTY_BITS) % P as u128) as u32
}

/// Convert a `u32` value from monty mode.
#[inline]
#[must_use]
pub const fn from_monty(x: u32) -> u32 {
    monty_reduce(x as u64)
}

/// Montgomery reduction of a value in `0..P << MONTY_BITS`.
#[inline]
#[must_use]
const fn monty_reduce(x: u64) -> u32 {
    let t = x.wrapping_mul(MONTY_MU as u64) & (MONTY_MASK as u64);
    let u = t * (P as u64);

    let (x_sub_u, over) = x.overflowing_sub(u);
    let x_sub_u_hi = (x_sub_u >> MONTY_BITS) as u32;
    let corr = if over { P } else { 0 };
    x_sub_u_hi.wrapping_add(corr)
}

/// Squares the base N number of times and multiplies the result by the tail value.
#[inline(always)]
fn exp<const N: u32>(base: u32) -> u32 {
    base.exp_power_of_2_reduce(N, BabyBearModulus)
}

#[inline(always)]
fn mul(a: u32, b: u32) -> u32 {
    a.mul_reduce(b, BabyBearModulus)
}

#[inline(always)]
fn square(value: u32) -> u32 {
    value.mul_reduce(value, BabyBearModulus)
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use rand_distr::{Distribution, Uniform};

    use crate::reduce::*;

    use super::*;

    type S = u32;
    type W = u64;
    const PW: W = P as W;

    #[test]
    fn test_baby_bear() {
        let dis = Uniform::new(0, P);
        let mut rng = thread_rng();

        let mut a_n = dis.sample(&mut rng);
        let mut b_n = loop {
            let t = dis.sample(&mut rng);
            if t != 0 {
                break t;
            }
        };

        let a_m = to_monty(a_n);
        let b_m = to_monty(b_n);

        while a_n > P {
            a_n -= P;
        }

        while b_n > P {
            b_n -= P;
        }

        assert_eq!(a_n, from_monty(a_m));

        assert_eq!(
            from_monty(a_m.add_reduce(b_m, BabyBearModulus)),
            ((a_n as W + b_n as W) % PW) as S
        );

        let mut temp = a_m;
        temp.add_reduce_assign(b_m, BabyBearModulus);
        assert_eq!(from_monty(temp), ((a_n as W + b_n as W) % PW) as S);

        assert_eq!(
            from_monty(a_m.sub_reduce(b_m, BabyBearModulus)),
            ((PW + a_n as W - b_n as W) % PW) as S
        );

        let mut temp = a_m;
        temp.sub_reduce_assign(b_m, BabyBearModulus);
        assert_eq!(from_monty(temp), ((PW + a_n as W - b_n as W) % PW) as S);

        assert_eq!(
            from_monty(a_m.neg_reduce(BabyBearModulus)),
            ((PW - a_n as W) % PW) as S
        );

        let mut temp = a_m;
        temp.neg_reduce_assign(BabyBearModulus);
        assert_eq!(from_monty(temp), ((PW - a_n as W) % PW) as S);

        assert_eq!(
            from_monty(a_m.mul_reduce(b_m, BabyBearModulus)),
            ((a_n as W * b_n as W) % PW) as S
        );

        let mut temp = a_m;
        temp.mul_reduce_assign(b_m, BabyBearModulus);
        assert_eq!(from_monty(temp), ((a_n as W * b_n as W) % PW) as S);

        let b_inv = b_m.inv_reduce(BabyBearModulus);
        assert_eq!(from_monty(b_m.mul_reduce(b_inv, BabyBearModulus)), 1);

        assert_eq!(
            a_m.div_reduce(b_m, BabyBearModulus),
            a_m.mul_reduce(b_inv, BabyBearModulus)
        );

        let mut temp = a_m;
        temp.div_reduce_assign(b_m, BabyBearModulus);
        assert_eq!(
            from_monty(temp),
            ((a_n as W * from_monty(b_inv) as W) % PW) as S
        );

        assert_eq!(a_m.exp_reduce(0, BabyBearModulus), 1);
        assert_eq!(a_m.exp_reduce(1, BabyBearModulus), a_m);
        assert_eq!(a_m.exp_reduce(b_m, BabyBearModulus), pow(a_m, b_m));

        let mut a_n: Vec<u32> = dis.sample_iter(&mut rng).take(5).collect();
        let mut b_n: Vec<u32> = dis.sample_iter(&mut rng).take(5).collect();
        let result = a_n.iter().zip(b_n.iter()).fold(0, |acc, (&a, &b)| {
            let mul = ((a as W * b as W) % PW) as S;
            ((acc as W + mul as W) % PW) as S
        });
        a_n.iter_mut().for_each(|x| *x = to_monty(*x));
        b_n.iter_mut().for_each(|x| *x = to_monty(*x));
        let ans = u32::dot_product_reduce(a_n, b_n, BabyBearModulus);
        assert_eq!(from_monty(ans), result);
    }

    fn pow(value: u32, exp: u32) -> u32 {
        let mut res = MONTY_ONE;
        let mut base = value;
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                res = res.mul_reduce(base, BabyBearModulus);
            }
            base = base.mul_reduce(base, BabyBearModulus);
            e >>= 1;
        }
        res
    }
}
