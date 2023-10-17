use std::fmt::Display;
use std::hash::Hash;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Zero};

use crate::field::Field;
use crate::modulo::{
    AddModulo, AddModuloAssign, DivModulo, DivModuloAssign, InvModulo, Modulus, MulModulo,
    MulModuloAssign, NegModulo, SubModulo, SubModuloAssign,
};
use crate::utils::Prime;

/// A finite Field type, whose inner size is 32bits.
///
/// Now, it's focused on the prime field.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Fp32<const P: u32>(u32);

impl<const P: u32> Hash for Fp32<P> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
        P.hash(state);
    }
}

impl<const P: u32> Field for Fp32<P> {}

impl<const P: u32> Display for Fp32<P> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[({})_{}]", self.0, P)
    }
}

/// A helper trait to get the modulus of the field.
pub trait BarrettConfig<const P: u32> {
    /// The modulus of the field.
    const MODULUS: Modulus<u32>;

    /// Get the modulus of the field.
    #[inline]
    fn modulus() -> Modulus<u32> {
        Self::MODULUS
    }

    /// Check [`Self`] is a prime field.
    #[inline]
    fn is_field() -> bool {
        Self::MODULUS.probably_prime(20)
    }
}

impl<const P: u32> BarrettConfig<P> for Fp32<P> {
    const MODULUS: Modulus<u32> = Modulus::<u32>::new(P);
}

impl<const P: u32> Fp32<P> {
    /// Creates a new [`Fp<P>`].
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }
}

impl<const P: u32> From<u32> for Fp32<P> {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl<const P: u32> Zero for Fp32<P> {
    #[inline]
    fn zero() -> Self {
        Self(Zero::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        Zero::is_zero(&self.0)
    }
}

impl<const P: u32> One for Fp32<P> {
    #[inline]
    fn one() -> Self {
        Self(One::one())
    }
}

impl<const P: u32> Add<Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add_modulo(rhs.0, P))
    }
}

impl<const P: u32> Add<&Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add_modulo(rhs.0, P))
    }
}

impl<const P: u32> AddAssign<Self> for Fp32<P> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_modulo_assign(rhs.0, P)
    }
}

impl<const P: u32> AddAssign<&Self> for Fp32<P> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.0.add_modulo_assign(rhs.0, P)
    }
}

impl<const P: u32> Sub<Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub_modulo(rhs.0, P))
    }
}

impl<const P: u32> Sub<&Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub_modulo(rhs.0, P))
    }
}

impl<const P: u32> SubAssign<Self> for Fp32<P> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_modulo_assign(rhs.0, P)
    }
}

impl<const P: u32> SubAssign<&Self> for Fp32<P> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.0.sub_modulo_assign(rhs.0, P)
    }
}

impl<const P: u32> Mul<Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(
            self.0
                .mul_modulo(rhs.0, &<Fp32<P> as BarrettConfig<P>>::modulus()),
        )
    }
}

impl<const P: u32> Mul<&Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(
            self.0
                .mul_modulo(rhs.0, &<Fp32<P> as BarrettConfig<P>>::modulus()),
        )
    }
}

impl<const P: u32> MulAssign<Self> for Fp32<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        self.0
            .mul_modulo_assign(rhs.0, &<Fp32<P> as BarrettConfig<P>>::modulus())
    }
}

impl<const P: u32> MulAssign<&Self> for Fp32<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0
            .mul_modulo_assign(rhs.0, &<Fp32<P> as BarrettConfig<P>>::modulus())
    }
}

impl<const P: u32> Div<Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn div(self, rhs: Self) -> Self::Output {
        Self(
            self.0
                .div_modulo(rhs.0, &<Fp32<P> as BarrettConfig<P>>::modulus()),
        )
    }
}

impl<const P: u32> Div<&Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn div(self, rhs: &Self) -> Self::Output {
        Self(
            self.0
                .div_modulo(rhs.0, &<Fp32<P> as BarrettConfig<P>>::modulus()),
        )
    }
}

impl<const P: u32> DivAssign<Self> for Fp32<P> {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        self.0
            .div_modulo_assign(rhs.0, &<Fp32<P> as BarrettConfig<P>>::modulus());
    }
}

impl<const P: u32> DivAssign<&Self> for Fp32<P> {
    #[inline]
    fn div_assign(&mut self, rhs: &Self) {
        self.0
            .div_modulo_assign(rhs.0, &<Fp32<P> as BarrettConfig<P>>::modulus());
    }
}

impl<const P: u32> Neg for Fp32<P> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg_modulo(P))
    }
}

impl<const P: u32> Inv for Fp32<P> {
    type Output = Self;

    #[inline]
    fn inv(self) -> Self::Output {
        Self(self.0.inv_modulo(P))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modulo::PowModulo;
    use rand::{prelude::*, thread_rng};

    #[test]
    fn test_fp_basic() {
        type F6 = Fp32<6>;
        assert!(!F6::is_field());

        type F5 = Fp32<5>;
        assert!(F5::is_field());
        assert_eq!(F5::from(4) + F5::from(3), F5::from(2));
        assert_eq!(F5::from(4) * F5::from(3), F5::from(2));
        assert_eq!(F5::from(4) - F5::from(3), F5::from(1));
        assert_eq!(F5::from(4) / F5::from(3), F5::from(3));
    }

    #[test]
    fn test_fp() {
        const P: u32 = 1000000513;

        assert!(P.checked_add(P).is_some());

        let distr = rand::distributions::Uniform::new_inclusive(0, P);
        let mut rng = thread_rng();

        type FF = Fp32<P>;
        assert!(FF::is_field());

        // add
        for _ in 0..100 {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let c = (a + b) % P;
            assert_eq!(FF::from(a) + FF::from(b), FF::from(c));
        }

        // add_assign
        for _ in 0..100 {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let c = (a + b) % P;
            let mut a = FF::from(a);
            a += FF::from(b);
            assert_eq!(a, FF::from(c));
        }

        // sub
        for _ in 0..100 {
            let a = rng.sample(distr);
            let b = rng.gen_range(0..=a);
            let c = (a - b) % P;
            assert_eq!(FF::from(a) - FF::from(b), FF::from(c));
        }

        // sub_assign
        for _ in 0..100 {
            let a = rng.sample(distr);
            let b = rng.gen_range(0..=a);
            let c = (a - b) % P;

            let mut a = FF::from(a);
            a -= FF::from(b);
            assert_eq!(a, FF::from(c));
        }

        // mul
        for _ in 0..100 {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let c = ((a as u64 * b as u64) % P as u64) as u32;
            assert_eq!(FF::from(a) * FF::from(b), FF::from(c));
        }

        // mul_assign
        for _ in 0..100 {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let c = ((a as u64 * b as u64) % P as u64) as u32;

            let mut a = FF::from(a);
            a *= FF::from(b);
            assert_eq!(a, FF::from(c));
        }

        // div
        for _ in 0..100 {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let b_inv = b.pow_modulo(P - 2, &Modulus::<u32>::new(P));
            let c = ((a as u64 * b_inv as u64) % P as u64) as u32;
            assert_eq!(FF::from(a) / FF::from(b), FF::from(c));
        }

        // div_assign
        for _ in 0..100 {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let b_inv = b.pow_modulo(P - 2, &Modulus::<u32>::new(P));
            let c = ((a as u64 * b_inv as u64) % P as u64) as u32;

            let mut a = FF::from(a);
            a /= FF::from(b);
            assert_eq!(a, FF::from(c));
        }

        // neg
        for _ in 0..100 {
            let a = rng.sample(distr);
            let a_neg = -FF::from(a);

            assert_eq!(FF::from(a) + a_neg, Zero::zero());
        }

        // inv
        for _ in 0..100 {
            let a = rng.sample(distr);
            let a_inv = a.pow_modulo(P - 2, &Modulus::<u32>::new(P));

            assert_eq!(FF::from(a).inv(), FF::from(a_inv));
            assert_eq!(FF::from(a) * FF::from(a_inv), One::one());
        }
    }
}
