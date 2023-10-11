use std::ops::{BitAnd, ShrAssign};

use num_traits::{One, Zero};

use crate::modulo::{MulModulo, PowModulo, PrimeModulus};

impl<T> PowModulo<&PrimeModulus<T>> for T
where
    T: Copy
        + Zero
        + One
        + PartialEq
        + PartialOrd
        + BitAnd<Output = Self>
        + ShrAssign<u32>
        + for<'m> MulModulo<&'m PrimeModulus<T>, Output = T>,
{
    type Exponent = Self;

    fn pow_modulo(self, mut exp: Self::Exponent, modulus: &PrimeModulus<T>) -> Self {
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
            if (exp & Self::one()) != Self::zero() {
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
