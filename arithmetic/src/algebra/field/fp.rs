use std::ops::{Add, Mul, Neg};

use num_traits::{One, Zero};

use crate::{
    algebra::{AddAssociativity, AddCommutativity, MulAssociativity, MulCommutativity},
    modulo::{FastAddModulo, MulModulo, NegModulo, PrimeModulus},
};

#[derive(Clone, Copy)]
pub struct Fp<const P: u64>(u64);

pub trait FpConfig<const P: u64> {
    const MODULUS: PrimeModulus;
    fn modulus() -> PrimeModulus {
        Self::MODULUS
    }
}

impl<const P: u64> FpConfig<P> for Fp<P> {
    const MODULUS: PrimeModulus = PrimeModulus::new(P);
}

impl<const P: u64> Fp<P> {
    pub fn new(value: u64) -> Self {
        Self(value)
    }
}

impl<const P: u64> Add<Self> for Fp<P> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add_modulo(rhs.0, <Fp<P> as FpConfig<P>>::modulus()))
    }
}

impl<const P: u64> AddAssociativity for Fp<P> {}

impl<const P: u64> Zero for Fp<P> {
    fn zero() -> Self {
        Self(Zero::zero())
    }

    fn is_zero(&self) -> bool {
        Zero::is_zero(&self.0)
    }
}

impl<const P: u64> Neg for Fp<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg_modulo(<Fp<P> as FpConfig<P>>::modulus()))
    }
}

impl<const P: u64> AddCommutativity for Fp<P> {}

impl<const P: u64> Mul<Self> for Fp<P> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul_modulo(rhs.0, <Fp<P> as FpConfig<P>>::modulus()))
    }
}

impl<const P: u64> MulAssociativity for Fp<P> {}

impl<const P: u64> One for Fp<P> {
    fn one() -> Self {
        Self(One::one())
    }
}

impl<const P: u64> MulCommutativity for Fp<P> {}
