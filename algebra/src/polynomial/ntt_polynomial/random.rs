use rand::{CryptoRng, Rng};
use rand_distr::Distribution;

use crate::{Field, FieldUniformSampler};

use super::NTTPolynomial;

impl<F: Field> NTTPolynomial<F> {
    /// Generate a random [`NTTPolynomial<F>`].
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

    /// Generate a random [`NTTPolynomial<F>`]  with a specified distribution `dis`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, rng: &mut R, distribution: D) -> Self
    where
        R: Rng + CryptoRng,
        D: Distribution<F>,
    {
        Self::new(distribution.sample_iter(rng).take(n).collect())
    }
}
