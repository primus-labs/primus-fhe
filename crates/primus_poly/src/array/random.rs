use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_reduce::Modulus;
use rand::distr::{Distribution, Uniform};

use super::{Array, ArrayMut};

impl<T: FheUint> Array<T> {
    /// Generate a random [`Array<T>`].
    #[inline]
    pub fn random<M, R>(n: usize, modulus: M, rng: &mut R) -> Self
    where
        M: Modulus<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        Self(
            modulus
                .uniform_distribution()
                .sample_iter(rng)
                .take(n)
                .collect(),
        )
    }

    /// Generate a random [`Array<T>`] with a specified `distribution`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, distribution: &D, rng: &mut R) -> Self
    where
        D: Distribution<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        Self(distribution.sample_iter(rng).take(n).collect())
    }

    /// Generate a random binary [`Array<T>`].
    #[inline]
    pub fn random_binary<R>(length: usize, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_binary_values(length, rng))
    }

    /// Generate a random ternary [`Array<T>`].
    #[inline]
    pub fn random_ternary<R>(minus_one: T, length: usize, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_ternary_values(minus_one, length, rng))
    }

    /// Generate a random [`Array<T>`] with discrete gaussian distribution.
    #[inline]
    pub fn random_gaussian<R>(length: usize, gaussian: &DiscreteGaussian<T>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(gaussian.sample_iter(rng).take(length).collect())
    }
}

impl<'a, T: FheUint> ArrayMut<'a, T> {
    /// Fill a random [`ArrayMut<'a, T>`].
    #[inline]
    pub fn random_assign<R>(&mut self, modulus_minus_one: T, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let distr = Uniform::new_inclusive(T::ZERO, modulus_minus_one).unwrap();
        self.iter_mut()
            .zip(distr.sample_iter(rng))
            .for_each(|(a, b)| *a = b);
    }

    /// Fill a random [`ArrayMut<'a, T>`] with a specified `distribution`.
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

    /// Fill a random binary [`ArrayMut<'a, T>`].
    #[inline]
    pub fn random_binary_assign<R>(&mut self, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_binary_values_to(self.0, rng)
    }

    /// Fill a random ternary [`ArrayMut<'a, T>`].
    #[inline]
    pub fn random_ternary_assign<R>(&mut self, minus_one: T, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_ternary_values_to(self.0, minus_one, rng)
    }

    /// Fill a random [`ArrayMut<'a, T>`] with discrete gaussian distribution.
    #[inline]
    pub fn random_gaussian_assign<R>(&mut self, gaussian: &DiscreteGaussian<T>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.iter_mut()
            .zip(gaussian.sample_iter(rng))
            .for_each(|(a, b)| *a = b);
    }
}
