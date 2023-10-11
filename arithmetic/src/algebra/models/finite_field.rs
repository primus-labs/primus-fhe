use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Zero};

use crate::{
    modulo::{
        AddModulo, AddModuloAssign, DivModulo, DivModuloAssign, InvModulo, MulModulo,
        MulModuloAssign, NegModulo, PrimeModulus, SubModulo, SubModuloAssign,
    },
    number_theory::Prime,
};

/// The inner element type of [`Fp<P>`].
pub type FpElement = u32;

/// A finite Field type, whose inner size is defined by [`FpElement`].
///
/// Now, it's focused on the prime field.
#[derive(Clone, Copy, Debug)]
pub struct Fp<const P: FpElement>(FpElement);

/// A helper trait to get the modulus of the field.
pub trait FpModulus<const P: FpElement> {
    /// The modulus of the field.
    const MODULUS: PrimeModulus<FpElement>;

    /// Get the modulus of the field.
    fn modulus() -> PrimeModulus<FpElement> {
        Self::MODULUS
    }

    /// Check [`Self`] is a prime field.
    fn is_field() -> bool {
        P.is_power_of_two() || Self::MODULUS.probably_prime(40)
    }
}

impl<const P: FpElement> FpModulus<P> for Fp<P> {
    const MODULUS: PrimeModulus<FpElement> = PrimeModulus::<FpElement>::new(P);
}

impl<const P: FpElement> Fp<P> {
    /// Creates a new [`Fp<P>`].
    pub fn new(value: FpElement) -> Self {
        Self(value)
    }
}

impl<const P: FpElement> From<FpElement> for Fp<P> {
    fn from(value: FpElement) -> Self {
        Self(value)
    }
}

impl<const P: FpElement> PartialEq for Fp<P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const P: FpElement> PartialOrd for Fp<P> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<const P: FpElement> Zero for Fp<P> {
    fn zero() -> Self {
        Self(Zero::zero())
    }

    fn is_zero(&self) -> bool {
        Zero::is_zero(&self.0)
    }
}

impl<const P: FpElement> One for Fp<P> {
    fn one() -> Self {
        Self(One::one())
    }
}

impl<const P: FpElement> Add<Self> for Fp<P> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add_modulo(rhs.0, P))
    }
}

impl<const P: FpElement> AddAssign<Self> for Fp<P> {
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_modulo_assign(rhs.0, P)
    }
}

impl<const P: FpElement> Sub<Self> for Fp<P> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub_modulo(rhs.0, P))
    }
}

impl<const P: FpElement> SubAssign<Self> for Fp<P> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_modulo_assign(rhs.0, P)
    }
}

impl<const P: FpElement> Mul<Self> for Fp<P> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(
            self.0
                .mul_modulo(rhs.0, &<Fp<P> as FpModulus<P>>::modulus()),
        )
    }
}
impl<const P: FpElement> MulAssign<Self> for Fp<P> {
    fn mul_assign(&mut self, rhs: Self) {
        self.0
            .mul_modulo_assign(rhs.0, &<Fp<P> as FpModulus<P>>::modulus())
    }
}

impl<const P: FpElement> Div<Self> for Fp<P> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Self(
            self.0
                .div_modulo(rhs.0, &<Fp<P> as FpModulus<P>>::modulus()),
        )
    }
}

impl<const P: FpElement> DivAssign<Self> for Fp<P> {
    fn div_assign(&mut self, rhs: Self) {
        self.0
            .div_modulo_assign(rhs.0, &<Fp<P> as FpModulus<P>>::modulus());
    }
}

impl<const P: FpElement> Neg for Fp<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg_modulo(P))
    }
}

impl<const P: FpElement> Inv for Fp<P> {
    type Output = Self;

    fn inv(self) -> Self::Output {
        Self(self.0.inv_modulo(P))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::Field;

    #[test]
    fn test_fp() {
        type F6 = Fp<6>;
        assert!(F6::check_field_trait());
        assert!(!F6::is_field());

        type F5 = Fp<5>;
        assert!(F5::check_field_trait());
        assert!(F5::is_field());
        assert_eq!(F5::from(4) + F5::from(3), F5::from(2));
        assert_eq!(F5::from(4) * F5::from(3), F5::from(2));
        assert_eq!(F5::from(4) - F5::from(3), F5::from(1));
        assert_eq!(F5::from(4) / F5::from(3), F5::from(3));
    }
}
