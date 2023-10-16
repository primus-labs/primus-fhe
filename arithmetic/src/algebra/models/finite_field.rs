use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Zero};

use crate::{
    modulo::{
        AddModulo, AddModuloAssign, DivModulo, DivModuloAssign, InvModulo, Modulus, MulModulo,
        MulModuloAssign, NegModulo, SubModulo, SubModuloAssign,
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
    const MODULUS: Modulus<FpElement>;

    /// Get the modulus of the field.
    #[inline]
    fn modulus() -> Modulus<FpElement> {
        Self::MODULUS
    }

    /// Check [`Self`] is a prime field.
    #[inline]
    fn is_field() -> bool {
        P.is_power_of_two() || Self::MODULUS.probably_prime(40)
    }
}

impl<const P: FpElement> FpModulus<P> for Fp<P> {
    const MODULUS: Modulus<FpElement> = Modulus::<FpElement>::new(P);
}

impl<const P: FpElement> Fp<P> {
    /// Creates a new [`Fp<P>`].
    #[inline]
    pub fn new(value: FpElement) -> Self {
        Self(value)
    }
}

impl<const P: FpElement> From<FpElement> for Fp<P> {
    #[inline]
    fn from(value: FpElement) -> Self {
        Self(value)
    }
}

impl<const P: FpElement> PartialEq for Fp<P> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const P: FpElement> PartialOrd for Fp<P> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<const P: FpElement> Zero for Fp<P> {
    #[inline]
    fn zero() -> Self {
        Self(Zero::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        Zero::is_zero(&self.0)
    }
}

impl<const P: FpElement> One for Fp<P> {
    #[inline]
    fn one() -> Self {
        Self(One::one())
    }
}

impl<const P: FpElement> Add<Self> for Fp<P> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add_modulo(rhs.0, P))
    }
}

impl<const P: FpElement> AddAssign<Self> for Fp<P> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_modulo_assign(rhs.0, P)
    }
}

impl<const P: FpElement> Sub<Self> for Fp<P> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub_modulo(rhs.0, P))
    }
}

impl<const P: FpElement> SubAssign<Self> for Fp<P> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_modulo_assign(rhs.0, P)
    }
}

impl<const P: FpElement> Mul<Self> for Fp<P> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(
            self.0
                .mul_modulo(rhs.0, &<Fp<P> as FpModulus<P>>::modulus()),
        )
    }
}
impl<const P: FpElement> MulAssign<Self> for Fp<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        self.0
            .mul_modulo_assign(rhs.0, &<Fp<P> as FpModulus<P>>::modulus())
    }
}

impl<const P: FpElement> Div<Self> for Fp<P> {
    type Output = Self;

    #[inline]
    fn div(self, rhs: Self) -> Self::Output {
        Self(
            self.0
                .div_modulo(rhs.0, &<Fp<P> as FpModulus<P>>::modulus()),
        )
    }
}

impl<const P: FpElement> DivAssign<Self> for Fp<P> {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        self.0
            .div_modulo_assign(rhs.0, &<Fp<P> as FpModulus<P>>::modulus());
    }
}

impl<const P: FpElement> Neg for Fp<P> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg_modulo(P))
    }
}

impl<const P: FpElement> Inv for Fp<P> {
    type Output = Self;

    #[inline]
    fn inv(self) -> Self::Output {
        Self(self.0.inv_modulo(P))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{algebra::Field, modulo::PowModulo};
    use rand::{prelude::*, thread_rng};

    #[test]
    fn test_fp_basic() {
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

    #[test]
    fn test_fp() {
        const P: u32 = 1000000513;

        assert!(P.checked_add(P).is_some());

        let distr = rand::distributions::Uniform::new_inclusive(0, P);
        let mut rng = thread_rng();

        type FF = Fp<P>;
        assert!(FF::check_field_trait());
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
            let b_inv = b.pow_modulo(P - 2, &Modulus::<FpElement>::new(P));
            let c = ((a as u64 * b_inv as u64) % P as u64) as u32;
            assert_eq!(FF::from(a) / FF::from(b), FF::from(c));
        }

        // div_assign
        for _ in 0..100 {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let b_inv = b.pow_modulo(P - 2, &Modulus::<FpElement>::new(P));
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
            let a_inv = a.pow_modulo(P - 2, &Modulus::<FpElement>::new(P));

            assert_eq!(FF::from(a).inv(), FF::from(a_inv));
            assert_eq!(FF::from(a) * FF::from(a_inv), One::one());
        }
    }
}
