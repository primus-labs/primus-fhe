use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Zero};

use crate::{
    modulo::{
        DivModulo, DivModuloAssign, FastAddModulo, FastAddModuloAssign, FastSubModulo,
        FastSubModuloAssign, InvModulo, MulModulo, MulModuloAssign, NegModulo, PrimeModulus,
    },
    number_theory::Prime,
};

type Element = u32;

#[derive(Clone, Copy, Debug)]
pub struct Fp<const P: Element>(Element);

pub trait FpModulus<const P: Element> {
    const MODULUS: PrimeModulus<Element>;

    fn modulus() -> PrimeModulus<Element> {
        Self::MODULUS
    }

    fn is_field() -> bool {
        P.is_power_of_two() || Self::MODULUS.probably_prime(40)
    }
}

impl<const P: Element> FpModulus<P> for Fp<P> {
    const MODULUS: PrimeModulus<Element> = PrimeModulus::<Element>::new(P);
}

impl<const P: Element> Fp<P> {
    pub fn new(value: Element) -> Self {
        Self(value)
    }
}

impl<const P: Element> From<Element> for Fp<P> {
    fn from(value: Element) -> Self {
        Self(value)
    }
}

impl<const P: Element> PartialEq for Fp<P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const P: Element> PartialOrd for Fp<P> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<const P: Element> Zero for Fp<P> {
    fn zero() -> Self {
        Self(Zero::zero())
    }

    fn is_zero(&self) -> bool {
        Zero::is_zero(&self.0)
    }
}

impl<const P: Element> One for Fp<P> {
    fn one() -> Self {
        Self(One::one())
    }
}

impl<const P: Element> Add<Self> for Fp<P> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add_modulo(rhs.0, P))
    }
}

impl<const P: Element> AddAssign<Self> for Fp<P> {
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_modulo_assign(rhs.0, P)
    }
}

impl<const P: Element> Sub<Self> for Fp<P> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub_modulo(rhs.0, P))
    }
}

impl<const P: Element> SubAssign<Self> for Fp<P> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_modulo_assign(rhs.0, P)
    }
}

impl<const P: Element> Mul<Self> for Fp<P> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(
            self.0
                .mul_modulo(rhs.0, &<Fp<P> as FpModulus<P>>::modulus()),
        )
    }
}
impl<const P: Element> MulAssign<Self> for Fp<P> {
    fn mul_assign(&mut self, rhs: Self) {
        self.0
            .mul_modulo_assign(rhs.0, &<Fp<P> as FpModulus<P>>::modulus())
    }
}

impl<const P: Element> Div<Self> for Fp<P> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Self(
            self.0
                .div_modulo(rhs.0, &<Fp<P> as FpModulus<P>>::modulus()),
        )
    }
}

impl<const P: Element> DivAssign<Self> for Fp<P> {
    fn div_assign(&mut self, rhs: Self) {
        self.0
            .div_modulo_assign(rhs.0, &<Fp<P> as FpModulus<P>>::modulus());
    }
}

impl<const P: Element> Neg for Fp<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg_modulo(P))
    }
}

impl<const P: Element> Inv for Fp<P> {
    type Output = Self;

    fn inv(self) -> Self::Output {
        Self(self.0.inv_modulo(P))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::field::Field;

    #[test]
    fn test_fp() {
        type F6 = Fp<6>;
        assert!(F6::has_impl_field_traits());
        assert!(!F6::is_field());

        type F5 = Fp<5>;
        assert!(F5::has_impl_field_traits());
        assert!(F5::is_field());
        assert_eq!(F5::from(4) + F5::from(3), F5::from(2));
        assert_eq!(F5::from(4) * F5::from(3), F5::from(2));
        assert_eq!(F5::from(4) - F5::from(3), F5::from(1));
        assert_eq!(F5::from(4) / F5::from(3), F5::from(3));
    }
}
