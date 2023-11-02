use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Pow, Zero};
use rand::{thread_rng, Rng};

use crate::field::{Field, NTTField};
use crate::modulo_traits::{
    AddModulo, AddModuloAssign, DivModulo, DivModuloAssign, InvModulo, MulModulo, MulModuloAssign,
    NegModulo, PowModulo, SubModulo, SubModuloAssign,
};
use crate::modulus::{Modulus, MulModuloFactor};
use crate::transformation::NTTTable;
use crate::utils::{Prime, ReverseLsbs};

use super::{MulFactor, PrimeField, RootFactor};

/// A finite Field type, whose inner size is 32bits.
///
/// Now, it's focused on the prime field.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Fp32<const P: u32>(u32);

impl<const P: u32> std::fmt::Display for Fp32<P> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[({})_{}]", self.0, P)
    }
}

/// A helper trait to get the modulus of the field.
pub trait BarrettConfig<const P: u32> {
    /// The modulus of the field.
    const BARRETT_MODULUS: Modulus<u32>;

    /// Get the modulus of the field.
    #[inline]
    fn barrett_modulus() -> Modulus<u32> {
        Self::BARRETT_MODULUS
    }
}

impl<const P: u32> BarrettConfig<P> for Fp32<P> {
    const BARRETT_MODULUS: Modulus<u32> = Modulus::<u32>::new(P);
}

impl<const P: u32> Fp32<P> {
    /// Creates a new \[`Fp32<P>`\].
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
        Self(self.0.add_reduce(rhs.0, P))
    }
}

impl<const P: u32> Add<&Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add_reduce(rhs.0, P))
    }
}

impl<const P: u32> AddAssign<Self> for Fp32<P> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_reduce_assign(rhs.0, P)
    }
}

impl<const P: u32> AddAssign<&Self> for Fp32<P> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.0.add_reduce_assign(rhs.0, P)
    }
}

impl<const P: u32> Sub<Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub_reduce(rhs.0, P))
    }
}

impl<const P: u32> Sub<&Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub_reduce(rhs.0, P))
    }
}

impl<const P: u32> SubAssign<Self> for Fp32<P> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_reduce_assign(rhs.0, P)
    }
}

impl<const P: u32> SubAssign<&Self> for Fp32<P> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.0.sub_reduce_assign(rhs.0, P)
    }
}

impl<const P: u32> Mul<Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul_reduce(rhs.0, &Self::BARRETT_MODULUS))
    }
}

impl<const P: u32> Mul<&Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul_reduce(rhs.0, &Self::BARRETT_MODULUS))
    }
}

impl<const P: u32> MulAssign<Self> for Fp32<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        self.0.mul_reduce_assign(rhs.0, &Self::BARRETT_MODULUS)
    }
}

impl<const P: u32> MulAssign<&Self> for Fp32<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0.mul_reduce_assign(rhs.0, &Self::BARRETT_MODULUS)
    }
}

impl<const P: u32> Div<Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn div(self, rhs: Self) -> Self::Output {
        Self(self.0.div_reduce(rhs.0, &Self::BARRETT_MODULUS))
    }
}

impl<const P: u32> Div<&Self> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn div(self, rhs: &Self) -> Self::Output {
        Self(self.0.div_reduce(rhs.0, &Self::BARRETT_MODULUS))
    }
}

impl<const P: u32> DivAssign<Self> for Fp32<P> {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        self.0.div_reduce_assign(rhs.0, &Self::BARRETT_MODULUS);
    }
}

impl<const P: u32> DivAssign<&Self> for Fp32<P> {
    #[inline]
    fn div_assign(&mut self, rhs: &Self) {
        self.0.div_reduce_assign(rhs.0, &Self::BARRETT_MODULUS);
    }
}

impl<const P: u32> Neg for Fp32<P> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg_reduce(P))
    }
}

impl<const P: u32> Inv for Fp32<P> {
    type Output = Self;

    #[inline]
    fn inv(self) -> Self::Output {
        Self(self.0.inv_reduce(P))
    }
}

impl<const P: u32> Pow<<Self as Field>::Order> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn pow(self, rhs: <Self as Field>::Order) -> Self::Output {
        Self(self.0.pow_reduce(rhs, &Self::BARRETT_MODULUS))
    }
}

impl<const P: u32> Field for Fp32<P> {
    type Order = u32;
    type Modulus = u32;

    #[inline]
    fn order() -> Self::Order {
        P
    }

    #[inline]
    fn modulus() -> Self::Modulus {
        P
    }
}

impl<const P: u32> PrimeField for Fp32<P> {
    /// Check [`Self`] is a prime field.
    #[inline]
    fn is_prime_field() -> bool {
        <Self as BarrettConfig<P>>::BARRETT_MODULUS.probably_prime(20)
    }
}

impl<const P: u32> NTTField for Fp32<P> {
    type Table = NTTTable<Self>;

    type Root = MulFactor<Self>;

    type Degree = u32;

    #[inline]
    fn is_primitive_root(root: Self, degree: Self::Degree) -> bool {
        debug_assert!(root.0 < P);
        assert!(
            degree > 1 && degree.is_power_of_two(),
            "degree must be a power of two and bigger than 1"
        );

        if root.is_zero() {
            return false;
        }

        root.pow(degree >> 1).0 == P - 1
    }

    fn try_primitive_root(degree: Self::Degree) -> Result<Self, crate::AlgebraError> {
        // p-1
        let modulus_sub_one = P - 1;

        // (p-1)/n
        let quotient = modulus_sub_one / degree;

        // (p-1) must be divisible by n
        if modulus_sub_one != quotient * degree {
            return Err(crate::AlgebraError::NoPrimitiveRoot {
                degree: degree.to_string(),
                modulus: P.to_string(),
            });
        }

        let mut rng = thread_rng();
        let distr = rand::distributions::Uniform::new_inclusive(2, P - 1);

        let mut w = Zero::zero();

        if (0..100).any(|_| {
            w = Self(rng.sample(distr)).pow(quotient);
            Self::is_primitive_root(w, degree)
        }) {
            Ok(w)
        } else {
            Err(crate::AlgebraError::NoPrimitiveRoot {
                degree: degree.to_string(),
                modulus: P.to_string(),
            })
        }
    }

    fn try_minimal_primitive_root(degree: Self::Degree) -> Result<Self, crate::AlgebraError> {
        let mut root = Self::try_primitive_root(degree)?;

        let generator_sq = root.square();
        let mut current_generator = root;

        for _ in 0..degree {
            if current_generator < root {
                root = current_generator;
            }

            current_generator *= generator_sq;
        }

        Ok(root)
    }

    fn generate_ntt_table(log_n: u32) -> Result<NTTTable<Self>, crate::AlgebraError> {
        let n = 1usize << log_n;

        let root = Self::try_minimal_primitive_root((n * 2).try_into().unwrap())?;
        let inv_root = root.inv();

        let root_factor = <Self as NTTField>::Root::new(root);
        let mut power = root;

        let mut root_powers = vec![<Self as NTTField>::Root::default(); n];
        root_powers[0].set(Self::one());
        for i in 1..n {
            root_powers[i.reverse_lsbs(log_n)].set(power);
            power *= root_factor;
        }

        let inv_root_factor = <Self as NTTField>::Root::new(inv_root);
        let mut inv_root_powers = vec![<Self as NTTField>::Root::default(); n];
        power = inv_root;

        inv_root_powers[0].set(Self::one());
        for i in 1..n {
            inv_root_powers[(i - 1).reverse_lsbs(log_n) + 1].set(power);
            power *= inv_root_factor;
        }
        let inv_degree = <Self as NTTField>::Root::new(Self(n as u32).inv());

        Ok(NTTTable::new(
            root,
            inv_root,
            log_n,
            n,
            inv_degree,
            root_powers,
            inv_root_powers,
        ))
    }
}

impl<const P: u32> RootFactor<Fp32<P>> for MulFactor<Fp32<P>> {
    /// Constructs a [`MulFactor<Fp32<P>>`].
    #[inline]
    fn new(value: Fp32<P>) -> Self {
        Self {
            value,
            quotient: Fp32((((value.0 as u64) << 32) / P as u64) as u32),
        }
    }

    /// Resets the content of [`MulFactor<Fp32<P>>`].
    #[inline]
    fn set(&mut self, value: Fp32<P>) {
        self.value = value;
        self.quotient = Fp32((((value.0 as u64) << 32) / P as u64) as u32);
    }
}

impl<const P: u32> Mul<MulFactor<Self>> for Fp32<P> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: MulFactor<Self>) -> Self::Output {
        let r = MulModuloFactor::<u32> {
            value: rhs.value.0,
            quotient: rhs.quotient.0,
        };

        Self(self.0.mul_reduce(r, P))
    }
}

impl<const P: u32> MulAssign<MulFactor<Self>> for Fp32<P> {
    #[inline]
    fn mul_assign(&mut self, rhs: MulFactor<Self>) {
        let r = MulModuloFactor::<u32> {
            value: rhs.value.0,
            quotient: rhs.quotient.0,
        };

        self.0.mul_reduce_assign(r, P);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modulo_traits::PowModulo;
    use rand::thread_rng;

    #[test]
    fn test_fp_basic() {
        type F6 = Fp32<6>;
        assert!(!F6::is_prime_field());

        type F5 = Fp32<5>;
        assert!(F5::is_prime_field());
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
        assert!(FF::is_prime_field());

        let round = 5;

        // add
        for _ in 0..round {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let c = (a + b) % P;
            assert_eq!(FF::from(a) + FF::from(b), FF::from(c));
        }

        // add_assign
        for _ in 0..round {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let c = (a + b) % P;
            let mut a = FF::from(a);
            a += FF::from(b);
            assert_eq!(a, FF::from(c));
        }

        // sub
        for _ in 0..round {
            let a = rng.sample(distr);
            let b = rng.gen_range(0..=a);
            let c = (a - b) % P;
            assert_eq!(FF::from(a) - FF::from(b), FF::from(c));
        }

        // sub_assign
        for _ in 0..round {
            let a = rng.sample(distr);
            let b = rng.gen_range(0..=a);
            let c = (a - b) % P;

            let mut a = FF::from(a);
            a -= FF::from(b);
            assert_eq!(a, FF::from(c));
        }

        // mul
        for _ in 0..round {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let c = ((a as u64 * b as u64) % P as u64) as u32;
            assert_eq!(FF::from(a) * FF::from(b), FF::from(c));
        }

        // mul_assign
        for _ in 0..round {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let c = ((a as u64 * b as u64) % P as u64) as u32;

            let mut a = FF::from(a);
            a *= FF::from(b);
            assert_eq!(a, FF::from(c));
        }

        // div
        for _ in 0..round {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let b_inv = b.pow_reduce(P - 2, &Modulus::<u32>::new(P));
            let c = ((a as u64 * b_inv as u64) % P as u64) as u32;
            assert_eq!(FF::from(a) / FF::from(b), FF::from(c));
        }

        // div_assign
        for _ in 0..round {
            let a = rng.sample(distr);
            let b = rng.sample(distr);
            let b_inv = b.pow_reduce(P - 2, &Modulus::<u32>::new(P));
            let c = ((a as u64 * b_inv as u64) % P as u64) as u32;

            let mut a = FF::from(a);
            a /= FF::from(b);
            assert_eq!(a, FF::from(c));
        }

        // neg
        for _ in 0..round {
            let a = rng.sample(distr);
            let a_neg = -FF::from(a);

            assert_eq!(FF::from(a) + a_neg, Zero::zero());
        }

        // inv
        for _ in 0..round {
            let a = rng.sample(distr);
            let a_inv = a.pow_reduce(P - 2, &Modulus::<u32>::new(P));

            assert_eq!(FF::from(a).inv(), FF::from(a_inv));
            assert_eq!(FF::from(a) * FF::from(a_inv), One::one());
        }
    }
}
