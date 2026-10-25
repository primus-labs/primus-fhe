use primus_data::RawData;
use primus_integer::FheUint;
use primus_reduce::Modulus;
use rand::distr::Distribution;

use super::Polynomial;

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + FromIterator<T>,
    T: FheUint,
{
    /// Creates a [`Polynomial<S>`] with uniform residues under `modulus`.
    ///
    /// Samples are collected directly into `S` in coefficient order.
    #[must_use]
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

    /// Creates a [`Polynomial<S>`] by collecting samples from `distribution`.
    ///
    /// Samples are collected directly into `S` in coefficient order. The caller
    /// chooses a distribution encoding the intended coefficient residues.
    #[must_use]
    #[inline]
    pub fn random_with_distribution<R, D>(poly_length: usize, distribution: &D, rng: &mut R) -> Self
    where
        D: Distribution<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        Self(distribution.sample_iter(rng).take(poly_length).collect())
    }
}
