use primus_data::{DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_reduce::Modulus;
use rand::distr::Distribution;

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Generate a random [`NttPolynomial<S>`].
    #[inline]
    pub fn random<M, R>(poly_length: usize, modulus: M, rng: &mut R) -> Self
    where
        M: Modulus<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        Self(
            modulus
                .uniform_distribution()
                .sample_iter(rng)
                .take(poly_length)
                .collect(),
        )
    }

    /// Generate a random [`NttPolynomial<S>`]  with a specified distribution `distribution`.
    #[inline]
    pub fn random_with_distribution<R, D>(poly_length: usize, distribution: &D, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        D: Distribution<T>,
    {
        Self(distribution.sample_iter(rng).take(poly_length).collect())
    }
}

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Generate a random [`NttPolynomial<S>`].
    #[inline]
    pub fn random_assign<M, R>(&mut self, modulus: M, rng: &mut R)
    where
        M: Modulus<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.iter_mut()
            .zip(modulus.uniform_distribution().sample_iter(rng))
            .for_each(|(a, b)| *a = b);
    }

    /// Generate a random [`NttPolynomial<S>`] with a specified `distribution`.
    #[inline]
    pub fn random_with_distribution_assign<R, D>(&mut self, distribution: &D, rng: &mut R)
    where
        D: Distribution<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.iter_mut()
            .zip(distribution.sample_iter(rng))
            .for_each(|(a, b)| *a = b);
    }
}
