use num_traits::ConstZero;
use rand::{CryptoRng, Rng};
use rand_distr::{Distribution, Uniform};

use crate::{integer::UnsignedInteger, random::DiscreteGaussian};

use super::Polynomial;

impl<T: UnsignedInteger> Polynomial<T> {
    /// Returns a [Uniform] distribution over the values under the modulus.
    #[must_use]
    #[inline]
    pub fn uniform_distribution(modulus_minus_one: T) -> Uniform<T> {
        Uniform::new_inclusive(<T as ConstZero>::ZERO, modulus_minus_one)
    }

    /// Generate a random [`Polynomial<T>`] with a specified distribution `distr`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, distr: D, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
        D: Distribution<T>,
    {
        Self::new(distr.sample_iter(rng).take(n).collect())
    }

    /// Generate a random binary [`Polynomial<T>`].
    #[inline]
    pub fn random_binary<R>(coeff_count: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(crate::random::sample_binary_values(coeff_count, rng))
    }

    /// Generate a random ternary [`Polynomial<T>`].
    #[inline]
    pub fn random_ternary<R>(modulus_minus_one: T, coeff_count: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(crate::random::sample_ternary_values(
            modulus_minus_one,
            coeff_count,
            rng,
        ))
    }

    /// Generate a random [`Polynomial<T>`] with discrete gaussian distribution.
    #[inline]
    pub fn random_gaussian<R>(
        gaussian: DiscreteGaussian<T>,
        coeff_count: usize,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(gaussian.sample_iter(rng).take(coeff_count).collect())
    }

    /// Generate a random [`Polynomial<T>`].
    #[inline]
    pub fn random<R>(modulus_minus_one: T, coeff_count: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self {
            poly: Uniform::new_inclusive(<T as ConstZero>::ZERO, modulus_minus_one)
                .sample_iter(rng)
                .take(coeff_count)
                .collect(),
        }
    }
}
