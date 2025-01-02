use num_traits::ConstZero;
use rand::{CryptoRng, Rng};
use rand_distr::{Distribution, Uniform};

use crate::{integer::UnsignedInteger, reduce::Modulus};

use super::NumNttPolynomial;

impl<T: UnsignedInteger> NumNttPolynomial<T> {
    /// Generate a random [`NumNttPolynomial<T>`].
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
