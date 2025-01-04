use num_traits::ConstZero;
use rand::{CryptoRng, Rng};
use rand_distr::{Distribution, Uniform};

use crate::{integer::UnsignedInteger, random::DiscreteGaussian, reduce::Modulus};

use super::NumPolynomial;

impl<T: UnsignedInteger> NumPolynomial<T> {
    /// Generate a random [`NumPolynomial<T>`] with a specified distribution `distribution`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, distribution: D, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
        D: Distribution<T>,
    {
        Self::new(distribution.sample_iter(rng).take(n).collect())
    }

    /// Generate a random binary [`NumPolynomial<T>`].
    #[inline]
    pub fn random_binary<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(crate::random::sample_binary_values(n, rng))
    }

    /// Generate a random ternary [`NumPolynomial<T>`].
    #[inline]
    pub fn random_ternary<M, R>(n: usize, modulus: M, rng: &mut R) -> Self
    where
        M: Copy + Modulus<T>,
        R: Rng + CryptoRng,
    {
        Self::new(crate::random::sample_ternary_values(
            modulus.modulus_minus_one(),
            n,
            rng,
        ))
    }

    /// Generate a random [`NumPolynomial<T>`] with discrete gaussian distribution.
    #[inline]
    pub fn random_gaussian<R>(n: usize, gaussian: DiscreteGaussian<T>, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(gaussian.sample_iter(rng).take(n).collect())
    }

    /// Generate a random [`NumPolynomial<T>`].
    #[inline]
    pub fn random<M, R>(n: usize, modulus: M, rng: &mut R) -> Self
    where
        M: Copy + Modulus<T>,
        R: Rng + CryptoRng,
    {
        Self {
            data: Uniform::new_inclusive(<T as ConstZero>::ZERO, modulus.modulus_minus_one())
                .sample_iter(rng)
                .take(n)
                .collect(),
        }
    }
}
