use num_traits::ConstZero;
use rand::{CryptoRng, Rng};
use rand_distr::{Distribution, Uniform};

use crate::{Field, NttField};

use super::FieldNttPolynomial;

impl<F: NttField> FieldNttPolynomial<F> {
    /// Returns a [Uniform] distribution over the values of [Field].
    #[must_use]
    #[inline]
    pub fn uniform_distribution() -> Uniform<<F as Field>::ValueT> {
        Uniform::new_inclusive(
            <<F as Field>::ValueT as ConstZero>::ZERO,
            <F as Field>::MINUS_ONE,
        )
    }

    /// Generate a random [`FieldNttPolynomial<F>`].
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

    /// Generate a random [`FieldNttPolynomial<F>`]  with a specified distribution `dis`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, rng: &mut R, distribution: D) -> Self
    where
        R: Rng + CryptoRng,
        D: Distribution<<F as Field>::ValueT>,
    {
        Self::new(distribution.sample_iter(rng).take(n).collect())
    }
}
