use num_traits::ConstZero;
use rand::{CryptoRng, Rng};
use rand_distr::{Distribution, Uniform};

use crate::integer::UnsignedInteger;

use super::NttPolynomial;

impl<T: UnsignedInteger> NttPolynomial<T> {
    /// Returns a [Uniform] distribution under the modulus.
    #[must_use]
    #[inline]
    pub fn uniform_distribution(modulus_minus_one: T) -> Uniform<T> {
        Uniform::new_inclusive(<T as ConstZero>::ZERO, modulus_minus_one)
    }

    /// Generate a random [`NttPolynomial<T>`].
    #[inline]
    pub fn random<R>(modulus_minus_one: T, value_count: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self {
            values: Uniform::new_inclusive(<T as ConstZero>::ZERO, modulus_minus_one)
                .sample_iter(rng)
                .take(value_count)
                .collect(),
        }
    }

    /// Generate a random [`NttPolynomial<T>`]  with a specified distribution `dis`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, rng: &mut R, distribution: D) -> Self
    where
        R: Rng + CryptoRng,
        D: Distribution<T>,
    {
        Self::new(distribution.sample_iter(rng).take(n).collect())
    }
}
