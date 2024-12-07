use rand::{CryptoRng, Rng};
use rand_distr::Distribution;

use crate::{Field, FieldDiscreteGaussianSampler, FieldUniformSampler};

use super::Polynomial;

impl<F> Polynomial<F> {
    /// Generate a random [`Polynomial<F>`] with a specified distribution `dis`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, rng: &mut R, distribution: D) -> Self
    where
        R: Rng + CryptoRng,
        D: Distribution<F>,
    {
        Self::new(distribution.sample_iter(rng).take(n).collect())
    }
}

impl<F: Field> Polynomial<F> {
    /// Generate a random binary [`Polynomial<F>`].
    #[inline]
    pub fn random_with_binary<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(crate::utils::sample_binary_field_vec(n, rng))
    }

    /// Generate a random ternary [`Polynomial<F>`].
    #[inline]
    pub fn random_with_ternary<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(crate::utils::sample_ternary_field_vec(n, rng))
    }

    /// Generate a random [`Polynomial<F>`] with discrete gaussian distribution.
    #[inline]
    pub fn random_with_gaussian<R>(
        n: usize,
        rng: &mut R,
        gaussian: FieldDiscreteGaussianSampler,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        if gaussian.cbd_enable() {
            Self::new(crate::utils::sample_cbd_field_vec(n, rng))
        } else {
            Self::new(gaussian.sample_iter(rng).take(n).collect())
        }
    }

    /// Generate a random [`Polynomial<F>`].
    #[inline]
    pub fn random<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self {
            data: FieldUniformSampler::new()
                .sample_iter(rng)
                .take(n)
                .collect(),
        }
    }
}
