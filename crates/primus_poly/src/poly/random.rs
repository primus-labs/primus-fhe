use primus_data::{DataMut, DataOwned, RawData};
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_reduce::{Modulus, ReduceAddAssign};
use rand::distr::Distribution;

use crate::poly::PolynomialOwned;

use super::Polynomial;

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Generate a random [`Polynomial<S>`].
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

    /// Generate a random [`Polynomial<S>`] with a specified `distribution`.
    #[inline]
    pub fn random_with_distribution<R, D>(poly_length: usize, distribution: &D, rng: &mut R) -> Self
    where
        D: Distribution<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        Self(distribution.sample_iter(rng).take(poly_length).collect())
    }

    /// Generate a random [`Polynomial<S>`] with discrete gaussian distribution.
    #[inline]
    pub fn random_gaussian<R>(
        poly_length: usize,
        gaussian: &DiscreteGaussian<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(gaussian.sample_iter(rng).take(poly_length).collect())
    }
}

impl<T: FheUint> PolynomialOwned<T> {
    /// Generate a random binary [`PolynomialOwned<T>`].
    #[inline]
    pub fn random_binary<R>(poly_length: usize, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_binary_values(poly_length, rng))
    }

    /// Generate a random ternary [`PolynomialOwned<T>`].
    #[inline]
    pub fn random_ternary<R>(minus_one: T, poly_length: usize, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_ternary_values(
            minus_one,
            poly_length,
            rng,
        ))
    }
}

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Generate a random [`Polynomial<S>`].
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

    /// Generate a random [`Polynomial<S>`] with a specified `distribution`.
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

    /// Generate a random binary [`Polynomial<S>`].
    #[inline]
    pub fn random_binary_assign<R>(&mut self, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_binary_values_to(self.as_mut(), rng)
    }

    /// Generate a random ternary [`Polynomial<S>`].
    #[inline]
    pub fn random_ternary_assign<R>(&mut self, minus_one: T, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_ternary_values_to(self.as_mut(), minus_one, rng)
    }

    /// Generate a random [`Polynomial<S>`] with discrete gaussian distribution..
    #[inline]
    pub fn random_gaussian_assign<R>(&mut self, gaussian: &DiscreteGaussian<T>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.iter_mut()
            .zip(gaussian.sample_iter(rng))
            .for_each(|(a, b)| *a = b);
    }

    /// Generate a random [`Polynomial<S>`] with discrete gaussian distribution..
    #[inline]
    pub fn add_random_gaussian_assign<R, M>(
        &mut self,
        gaussian: &DiscreteGaussian<T>,
        modulus: M,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: Copy + ReduceAddAssign<T>,
    {
        self.iter_mut()
            .zip(gaussian.sample_iter(rng))
            .for_each(|(a, b)| modulus.reduce_add_assign(a, b));
    }
}
