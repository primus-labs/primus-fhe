use num_traits::ConstZero;
use rand::{CryptoRng, Rng};
use rand_distr::{Distribution, Uniform};

use crate::{random::DiscreteGaussian, Field};

use super::FieldPolynomial;

impl<F: Field> FieldPolynomial<F> {
    /// Returns a [Uniform] distribution over the values of [Field].
    #[must_use]
    #[inline]
    pub fn uniform_distribution() -> Uniform<<F as Field>::ValueT> {
        Uniform::new_inclusive(
            <<F as Field>::ValueT as ConstZero>::ZERO,
            <F as Field>::MINUS_ONE,
        )
    }

    /// Generate a random [`FieldPolynomial<F>`] with a specified `distribution`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, distribution: &D, rng: &mut R) -> Self
    where
        D: Distribution<<F as Field>::ValueT>,
        R: Rng + CryptoRng,
    {
        Self::new(distribution.sample_iter(rng).take(n).collect())
    }

    /// Generate a random binary [`FieldPolynomial<F>`].
    #[inline]
    pub fn random_binary<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(crate::random::sample_binary_values(n, rng))
    }

    /// Generate a random ternary [`FieldPolynomial<F>`].
    #[inline]
    pub fn random_ternary<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(crate::random::sample_ternary_values(
            <F as Field>::MINUS_ONE,
            n,
            rng,
        ))
    }

    /// Generate a random [`FieldPolynomial<F>`] with discrete gaussian distribution.
    #[inline]
    pub fn random_gaussian<R>(
        n: usize,
        gaussian: &DiscreteGaussian<<F as Field>::ValueT>,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(gaussian.sample_iter(rng).take(n).collect())
    }

    /// Generate a random [`FieldPolynomial<F>`].
    #[inline]
    pub fn random<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self {
            data: Self::uniform_distribution()
                .sample_iter(rng)
                .take(n)
                .collect(),
        }
    }
}
