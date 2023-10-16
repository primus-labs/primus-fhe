use std::ops::{BitAnd, ShrAssign};

use num_traits::{One, Zero};

use crate::modulo::{Modulus, MulModulo, PowModulo};

impl<T> PowModulo<&Modulus<T>> for T
where
    T: Copy
        + Zero
        + One
        + PartialOrd
        + BitAnd<Output = Self>
        + ShrAssign<u32>
        + for<'m> MulModulo<&'m Modulus<T>, Output = T>,
{
    type Exponent = Self;

    fn pow_modulo(self, mut exp: Self::Exponent, modulus: &Modulus<T>) -> Self {
        if exp.is_zero() {
            return Self::one();
        }

        debug_assert!(self < modulus.value());

        if exp.is_one() {
            return self;
        }

        let mut power: Self = self;
        let mut intermediate: Self = Self::one();
        loop {
            if !(exp & Self::one()).is_zero() {
                intermediate = intermediate.mul_modulo(power, modulus);
            }
            exp >>= 1;
            if exp.is_zero() {
                break;
            }
            power = power.mul_modulo(power, modulus);
        }
        intermediate
    }
}

#[cfg(test)]
mod tests {
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

        for _ in 0..100 {
            let base = rng.sample(distr);
            let exp = random();

            assert_eq!(
                simple_pow(base, exp, P),
                base.pow_modulo(exp as T, &modulus)
            );
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
