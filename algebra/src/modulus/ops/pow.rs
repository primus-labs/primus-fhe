use std::ops::ShrAssign;

use num_traits::{One, PrimInt};

use crate::modulo_traits::{MulModulo, PowModulo};
use crate::modulus::Modulus;
use crate::Bits;

impl<T, E> PowModulo<&Modulus<T>, E> for T
where
    T: Copy + One + PartialOrd + for<'m> MulModulo<&'m Modulus<T>, Output = T>,
    E: PrimInt + ShrAssign<u32> + Bits,
{
    fn pow_reduce(self, mut exp: E, modulus: &Modulus<T>) -> Self {
        if exp.is_zero() {
            return Self::one();
        }

        debug_assert!(self < modulus.value());

        let mut power: Self = self;

        let exp_trailing_zeros = exp.trailing_zeros();
        if exp_trailing_zeros > 0 {
            for _ in 0..exp_trailing_zeros {
                power = power.mul_reduce(power, modulus);
            }
            exp >>= exp_trailing_zeros;
        }

        if exp.is_one() {
            return power;
        }

        let mut intermediate: Self = power;
        for _ in 1..(E::N_BITS - exp.leading_zeros()) {
            exp >>= 1;
            power = power.mul_reduce(power, modulus);
            if !(exp & E::one()).is_zero() {
                intermediate = intermediate.mul_reduce(power, modulus);
            }
        }
        intermediate
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;
    use rand::{prelude::*, thread_rng};

    use super::*;

    type T = u32;
    type W = u64;

    #[test]
    fn test_pow_mod_simple() {
        const P: T = 1000000513;
        let modulus = Modulus::<T>::new(P);

        let distr = rand::distributions::Uniform::new_inclusive(0, P);
        let mut rng = thread_rng();

        for _ in 0..5 {
            let base = rng.sample(distr);
            let exp = random();

            assert_eq!(simple_pow(base, exp, P), base.pow_reduce(exp, &modulus));
        }
    }

    fn simple_pow(base: T, mut exp: u32, modulus: T) -> T {
        if exp.is_zero() {
            return 1;
        }

        debug_assert!(base < modulus);

        if exp.is_one() {
            return base;
        }

        let mut power: T = base;
        let mut intermediate: T = 1;
        loop {
            if exp & 1 != 0 {
                intermediate = ((intermediate as W * power as W) % modulus as W) as T;
            }
            exp >>= 1;
            if exp.is_zero() {
                break;
            }
            power = ((power as W * power as W) % modulus as W) as T;
        }
        intermediate
    }
}
