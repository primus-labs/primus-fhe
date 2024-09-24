//! impl Goldilocks Prime Modulus
//!
//! This is derived from the [plonky2](https://github.com/0xPolygonZero/plonky2/blob/main/field/src/goldilocks_field.rs).

use crate::reduce::{ExpPowOf2Reduce, MulReduce};

mod ops;

const EPSILON: u64 = (1 << 32) - 1;
/// The module for Goldilocks field
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// Goldilocks Prime Modulus.
///
/// Its order is 2^64 - 2^32 + 1.
/// ```ignore
/// P = 2**64 - EPSILON
///   = 2**64 - 2**32 + 1
///   = 2**32 * (2**32 - 1) + 1
/// ```
#[derive(Clone, Copy)]
pub struct GoldilocksModulus;

/// Convert back to a normal `u64` value.
#[inline]
pub fn to_canonical_u64(value: u64) -> u64 {
    let mut c = value;
    // We only need one condition subtraction, since 2 * ORDER would not fit in a u64.
    if c >= P {
        c -= P;
    }
    c
}

/// Returns the inverse of the field element, using Fermat's little theorem.
/// The inverse of `a` is computed as `a^(p-2)`, where `p` is the prime order of the field.
///
/// Mathematically, this is equivalent to:
///                $a^(p-1)     = 1 (mod p)$
///                $a^(p-2) * a = 1 (mod p)$
/// Therefore      $a^(p-2)     = a^-1 (mod p)$
///
/// The following code has been adapted from winterfell/math/src/field/f64/mod.rs
/// located at <https://github.com/facebook/winterfell>.
fn try_inverse(value: u64) -> Option<u64> {
    if value == 0 {
        return None;
    }

    // compute base^(P - 2) using 72 multiplications
    // The exponent P - 2 is represented in binary as:
    // 0b1111111111111111111111111111111011111111111111111111111111111111

    // compute base^11
    let t2 = mul(square(value), value);

    // compute base^111
    let t3 = mul(square(t2), value);

    // compute base^111111 (6 ones)
    // repeatedly square t3 3 times and multiply by t3
    let t6 = exp_acc::<3>(t3, t3);

    // compute base^111111111111 (12 ones)
    // repeatedly square t6 6 times and multiply by t6
    let t12 = exp_acc::<6>(t6, t6);

    // compute base^111111111111111111111111 (24 ones)
    // repeatedly square t12 12 times and multiply by t12
    let t24 = exp_acc::<12>(t12, t12);

    // compute base^1111111111111111111111111111111 (31 ones)
    // repeatedly square t24 6 times and multiply by t6 first. then square t30 and
    // multiply by base
    let t30 = exp_acc::<6>(t24, t6);
    let t31 = mul(square(t30), value);

    // compute base^111111111111111111111111111111101111111111111111111111111111111
    // repeatedly square t31 32 times and multiply by t31
    let t63 = exp_acc::<32>(t31, t31);

    // compute base^1111111111111111111111111111111011111111111111111111111111111111
    Some(mul(square(t63), value))
}

/// Fast addition modulo ORDER for x86-64.
/// This function is marked unsafe for the following reasons:
///   - It is only correct if x + y < 2**64 + ORDER = 0x1ffffffff00000001.
///   - It is only faster in some circumstances. In particular, on x86 it overwrites both inputs in
///     the registers, so its use is not recommended when either input will be used again.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    let res_wrapped: u64;
    let adjustment: u64;
    core::arch::asm!(
        "add {0}, {1}",
        // Trick. The carry flag is set iff the addition overflowed.
        // sbb x, y does x := x - y - CF. In our case, x and y are both {1:e}, so it simply does
        // {1:e} := 0xffffffff on overflow and {1:e} := 0 otherwise. {1:e} is the low 32 bits of
        // {1}; the high 32-bits are zeroed on write. In the end, we end up with 0xffffffff in {1}
        // on overflow; this happens be EPSILON.
        // Note that the CPU does not realize that the result of sbb x, x does not actually depend
        // on x. We must write the result to a register that we know to be ready. We have a
        // dependency on {1} anyway, so let's use it.
        "sbb {1:e}, {1:e}",
        inlateout(reg) x => res_wrapped,
        inlateout(reg) y => adjustment,
        options(pure, nomem, nostack),
    );

    // Add EPSILON == subtract ORDER.
    // Cannot overflow unless the assumption if x + y < 2**64 + ORDER is incorrect.
    res_wrapped + adjustment
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
const unsafe fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    let (res_wrapped, carry) = x.overflowing_add(y);
    // Below cannot overflow unless the assumption if x + y < 2**64 + ORDER is incorrect.
    res_wrapped + EPSILON * (carry as u64)
}

/// Reduces to a 64-bit value. The result might not be in canonical form; it could be in between the
/// field order and `2^64`.
#[inline]
#[allow(unused)]
fn reduce96((x_lo, x_hi): (u64, u32)) -> u64 {
    let t1 = x_hi as u64 * EPSILON;
    unsafe { add_no_canonicalize_trashing_input(x_lo, t1) }
}

/// Reduces to a 64-bit value. The result might not be in canonical form; it could be in between the
/// field order and `2^64`.
#[inline]
fn reduce128(x: u128) -> u64 {
    let (x_lo, x_hi) = split(x); // This is a no-op
    let x_hi_hi = x_hi >> 32;
    let x_hi_lo = x_hi & EPSILON;

    let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
    if borrow {
        t0 -= EPSILON; // Cannot underflow.
    }
    let t1 = x_hi_lo * EPSILON;
    unsafe { add_no_canonicalize_trashing_input(t0, t1) }
}

#[inline]
const fn split(x: u128) -> (u64, u64) {
    (x as u64, (x >> 64) as u64)
}

/// Squares the base N number of times and multiplies the result by the tail value.
#[inline(always)]
fn exp_acc<const N: u32>(base: u64, tail: u64) -> u64 {
    base.exp_power_of_2_reduce(N, GoldilocksModulus)
        .mul_reduce(tail, GoldilocksModulus)
}

#[inline(always)]
fn mul(a: u64, b: u64) -> u64 {
    a.mul_reduce(b, GoldilocksModulus)
}

#[inline(always)]
fn square(value: u64) -> u64 {
    value.mul_reduce(value, GoldilocksModulus)
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use rand_distr::{Distribution, Uniform};

    use crate::reduce::*;

    use super::*;

    type S = u64;
    type W = u128;
    const PW: W = P as W;

    #[test]
    fn test_baby_bear() {
        let dis = Uniform::new(0, P);
        let mut rng = thread_rng();

        let a = dis.sample(&mut rng);
        let b = loop {
            let t = dis.sample(&mut rng);
            if t != 0 {
                break t;
            }
        };

        assert_eq!(
            to_canonical_u64(a.add_reduce(b, GoldilocksModulus)),
            ((a as W + b as W) % PW) as S
        );

        let mut temp = a;
        temp.add_reduce_assign(b, GoldilocksModulus);
        assert_eq!(to_canonical_u64(temp), ((a as W + b as W) % PW) as S);

        assert_eq!(
            to_canonical_u64(a.sub_reduce(b, GoldilocksModulus)),
            ((PW + a as W - b as W) % PW) as S
        );

        let mut temp = a;
        temp.sub_reduce_assign(b, GoldilocksModulus);
        assert_eq!(to_canonical_u64(temp), ((PW + a as W - b as W) % PW) as S);

        assert_eq!(
            to_canonical_u64(a.neg_reduce(GoldilocksModulus)),
            ((PW - a as W) % PW) as S
        );

        let mut temp = a;
        temp.neg_reduce_assign(GoldilocksModulus);
        assert_eq!(to_canonical_u64(temp), ((PW - a as W) % PW) as S);

        assert_eq!(
            to_canonical_u64(a.mul_reduce(b, GoldilocksModulus)),
            ((a as W * b as W) % PW) as S
        );

        let mut temp = a;
        temp.mul_reduce_assign(b, GoldilocksModulus);
        assert_eq!(to_canonical_u64(temp), ((a as W * b as W) % PW) as S);

        let b_inv = b.inv_reduce(GoldilocksModulus);
        assert_eq!(to_canonical_u64(b.mul_reduce(b_inv, GoldilocksModulus)), 1);

        assert_eq!(
            to_canonical_u64(a.div_reduce(b, GoldilocksModulus)),
            to_canonical_u64(a.mul_reduce(b_inv, GoldilocksModulus))
        );

        let mut temp = a;
        temp.div_reduce_assign(b, GoldilocksModulus);
        assert_eq!(
            to_canonical_u64(temp),
            to_canonical_u64(a.mul_reduce(b_inv, GoldilocksModulus))
        );

        assert_eq!(to_canonical_u64(a.exp_reduce(0, GoldilocksModulus)), 1);
        assert_eq!(to_canonical_u64(a.exp_reduce(1, GoldilocksModulus)), a);
        assert_eq!(
            to_canonical_u64(a.exp_reduce(b, GoldilocksModulus)),
            pow(a, b)
        );
        let a: Vec<u64> = dis.sample_iter(&mut rng).take(5).collect();
        let b: Vec<u64> = dis.sample_iter(&mut rng).take(5).collect();
        let result = a.iter().zip(b.iter()).fold(0, |acc, (&a, &b)| {
            a.mul_reduce(b, GoldilocksModulus)
                .add_reduce(acc, GoldilocksModulus)
        });
        let ans = u64::dot_product_reduce(a, b, GoldilocksModulus);
        assert_eq!(to_canonical_u64(ans), result);
    }

    fn pow(value: u64, mut exp: u64) -> u64 {
        let mut res = 1;
        let mut base = value;
        while exp > 0 {
            if exp & 1 == 1 {
                res = res.mul_reduce(base, GoldilocksModulus);
            }
            base = base.mul_reduce(base, GoldilocksModulus);
            exp >>= 1;
        }
        res
    }
}
