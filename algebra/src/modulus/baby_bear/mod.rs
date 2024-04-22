mod ops;

/// The Baby Bear prime
/// This is the unique 31-bit prime with the highest possible 2 adicity (27).
pub(self) const P: u32 = 0x78000001;
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

const MONTY_ZERO: u32 = to_monty(0);
const MONTY_ONE: u32 = to_monty(1);
const MONTY_TWO: u32 = to_monty(2);
const MONTY_NEG_ONE: u32 = to_monty(P - 1);

// fn try_inverse(value: u32) -> Option<u32> {
//     if value == 0 {
//         return None;
//     }

//     // From Fermat's little theorem, in a prime field `F_p`, the inverse of `a` is `a^(p-2)`.
//     // Here p-2 = 2013265919 = 1110111111111111111111111111111_2.
//     // Uses 30 Squares + 7 Multiplications => 37 Operations total.

//     let p1 = value;
//     let p100000000 = p1.exp_power_of_2(8);
//     let p100000001 = p100000000 * p1;
//     let p10000000000000000 = p100000000.exp_power_of_2(8);
//     let p10000000100000001 = p10000000000000000 * p100000001;
//     let p10000000100000001000 = p10000000100000001.exp_power_of_2(3);
//     let p1000000010000000100000000 = p10000000100000001000.exp_power_of_2(5);
//     let p1000000010000000100000001 = p1000000010000000100000000 * p1;
//     let p1000010010000100100001001 = p1000000010000000100000001 * p10000000100000001000;
//     let p10000000100000001000000010 = p1000000010000000100000001.square();
//     let p11000010110000101100001011 = p10000000100000001000000010 * p1000010010000100100001001;
//     let p100000001000000010000000100 = p10000000100000001000000010.square();
//     let p111000011110000111100001111 = p100000001000000010000000100 * p11000010110000101100001011;
//     let p1110000111100001111000011110000 = p111000011110000111100001111.exp_power_of_2(4);
//     let p1110111111111111111111111111111 =
//         p1110000111100001111000011110000 * p111000011110000111100001111;

//     Some(p1110111111111111111111111111111)
// }

#[inline]
#[must_use]
const fn to_monty(x: u32) -> u32 {
    (((x as u64) << MONTY_BITS) % P as u64) as u32
}

#[inline]
#[must_use]
const fn from_monty(x: u32) -> u32 {
    monty_reduce(x as u64)
}

/// Montgomery reduction of a value in `0..P << MONTY_BITS`.
#[inline]
#[must_use]
pub(crate) const fn monty_reduce(x: u64) -> u32 {
    let t = x.wrapping_mul(MONTY_MU as u64) & (MONTY_MASK as u64);
    let u = t * (P as u64);

    let (x_sub_u, over) = x.overflowing_sub(u);
    let x_sub_u_hi = (x_sub_u >> MONTY_BITS) as u32;
    let corr = if over { P } else { 0 };
    x_sub_u_hi.wrapping_add(corr)
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use rand_distr::{Distribution, Uniform};

    use crate::reduce::{AddReduce, MulReduce, SubReduce};

    use super::*;

    const P64: u64 = P as u64;
    #[test]
    fn test_baby_bear() {
        let dis = Uniform::new(0, P);
        let mut rng = thread_rng();

        let a_n = dis.sample(&mut rng);
        let b_n = dis.sample(&mut rng);

        let a_m = to_monty(a_n);
        let b_m = to_monty(b_n);

        assert_eq!(
            from_monty(a_m.add_reduce(b_m, BabyBearModulus)),
            ((a_n as u64 + b_n as u64) % P64) as u32
        );

        assert_eq!(
            from_monty(a_m.sub_reduce(b_m, BabyBearModulus)),
            ((P64 + a_n as u64 - b_n as u64) % P64) as u32
        );

        assert_eq!(
            from_monty(a_m.mul_reduce(b_m, BabyBearModulus)),
            ((a_n as u64 * b_n as u64) % P64) as u32
        );
    }
}
